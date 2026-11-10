# Raw Artifact 영속 보존과 Provenance 완결

2026-10-21 (Asia/Seoul), `feature/dashboard/demo-polish`.

목표는 `Evidence → NormalizedEvent → raw_ref → Run Manifest → Raw Artifact → Source Record`를
실제로 재검증할 수 있게 만드는 것이다. 탐지 알고리즘·Extractor·LLM은 변경하지 않았다.

## 1. Run 007 원본 복구 가능 여부

결론: **복구된 것으로 인정하지 않으며 `event_verified`를 유지한다.**

| 확인 항목 | 결과 |
| --- | --- |
| 007 수집 객체 (`ING-0bfeefb5…`, ETag `0c4d9e69e493c05733b92997f8e5ece8`) | LocalStack `NoSuchKey`, 버킷 비어 있음 |
| 공식 패키지 Attack JSONL (`RUN-20260927-002`) | 643,201 bytes, 869 레코드, SHA-256 `78c4b4a2…6d8da`, `SHA256SUMS.csv`와 일치 |
| 공식 JSONL의 MD5 | `0c4d9e69…` = 007 Receipt의 ETag |
| 2026-10-20 QA 기록 | 업로드 직후 S3 객체 재스트리밍 SHA-256이 공식 JSONL과 같다고 기록 |
| 007 생성 시점 Manifest / Evidence 원본 | Worker TemporaryDirectory와 함께 소멸, 어디에도 없음 |

동일성을 뒷받침하는 정황은 강하지만 기준을 충족하지 못한다.

- ETag(MD5)는 충돌 저항성이 없는 S3 identity이며 신뢰 가능한 콘텐츠 해시가 아니다.
- QA 기록은 개발 산출물(`build/`)이며 시스템이 남긴 정본이 아니다.
- 가장 중요한 점은 **007 Run Manifest와 Raw identity의 연결이 남아 있지 않다**는 것이다.
  공식 Manifest는 `RUN-20260927-002`/`RAW-002`를 가리킨다.

Standalone Manifest는 결정적 구조라 재생성은 가능하다. 하지만 과거 정본처럼 등록하는 것은 금지
사항이므로 하지 않았다. 007/006/008의 행·Receipt·Workflow는 변경하지 않았다.

## 2. 기존 경로의 보존 위험

`Dashboard Upload → LocalStack S3 → SQS → Worker → Standalone → PostgreSQL`

- LocalStack은 `PERSISTENCE` 비활성이다(`docker-compose.localstack.yml` 주석). 볼륨이 있어도 재시작하면
  S3/SQS 상태가 사라진다. 격리 E2E에서 재시작 직후 `HeadObject`가 404였다.
- Worker 컨테이너에는 볼륨이 없고, Standalone `output_dir`는 Worker의 `TemporaryDirectory` 아래라
  처리 후 삭제된다. Run Manifest도 그 안에서 생성되고 함께 사라진다.
- `s3_object_receipts`에는 bucket/key/ETag만 있고 콘텐츠 SHA-256이 없다.
  `s3_object_sha256_v1`은 identity 해시다.
- R1 archive(`r1_archive_publications`)는 R1 Evidence outbox이며 S0 Raw 바이트를 보존하지 않는다.
  보존 대상이 달라 재사용하지 않고 저장 패턴(PostgreSQL 바이트, 무결성 재검증)만 따랐다.

## 3. 보존 구조

정본 저장소는 **PostgreSQL**이다. Run·Event·Fusion·Receipt와 같은 트랜잭션으로 커밋할 수 있는
유일한 기존 영속 저장소이며 이미 Docker volume과 백업 대상이다.

| 후보 | 판단 |
| --- | --- |
| LocalStack S3 | 재시작 시 유실. 최종 보존 장소로 사용하지 않음 |
| Worker 로컬 파일 | 컨테이너 볼륨 없음, DB 트랜잭션과 원자성 없음 |
| **PostgreSQL BYTEA (채택)** | Run/Receipt와 원자적 커밋, 기존 volume·`pg_dump`로 백업/복구 |
| 파일 복제본 (선택) | `IAE_RAW_ARCHIVE_MIRROR_ROOT`. 필수 복제본으로 검증하지만 복구 원천은 DB |
| 실제 S3 + Object Lock | 운영 전환 시 후보. 이번 단계는 AWS 호출 금지라 제외 |

Migration `015_raw_artifact_retention` (추가만 수행, 과거 Run backfill 없음):

- `raw_artifact_blobs`: `content_sha256` PK, `byte_size`, `content`. SQL CHECK로 실제
  `sha256(content)`와 길이가 일치해야 한다. 동일 콘텐츠는 한 번만 저장한다.
- `raw_run_archives`: Run별 참조다(PK `run_id`, FK `runs`). 필드는 ingest_id, bucket/object_key/e_tag
  (UNIQUE), raw_log_id, content_sha256, `artifact_uri = raw-db:sha256:<sha>`,
  Manifest 바이트와 SHA-256, `manifest_identity = raw-manifest:<run>:sha256:<sha>`,
  **생성 시점 Evidence 바이트**와 SHA-256, extractor 버전과 코드 SHA-256,
  `raw_format = sysmon_jsonl`/`sysmon_jsonl_v1`, source_metadata, mirror_required,
  archive_created_at이다.
- `raw_archive_audit`: 시스템 감사기록(`upload_prepared`, `uploaded`, `retained`, `verified`,
  `repaired`, `failed`, `degraded` + reason code). Human Workflow 기록이 아니다.
- 세 테이블 모두 UPDATE/DELETE 행 트리거와 **TRUNCATE 문장 트리거**로 append-only다.

ETag는 `e_tag` 컬럼에만 두고 SHA-256과 섞지 않는다. 원본 바이트는 변형·덮어쓰기하지 않는다.

## 4. 저장 순서와 실패 처리

1. **업로드 API**: 검증 후 PUT **이전에** 독립 트랜잭션으로 원본 blob과 `upload_prepared`를
   커밋한다. PUT에는 `IfNoneMatch="*"`와 메타데이터 `content-sha256`을 붙인다. ETag를 확인한 뒤
   `uploaded`를 기록한다. 보존이 실패하면 503이며 업로드 성공으로 보고하지 않는다.
2. **Worker**: Run·Event·Fusion 저장 → `raw_run_archives` 저장 → (설정 시) 복제본 원자적 게시 →
   Receipt 직전 재검증 → Receipt 저장 → **단일 COMMIT**. 보존이 실패하면 전체를 롤백하고
   `failed` 감사기록만 별도 커밋한다. 메시지는 삭제하지 않는다.
3. **조회**: 요청마다 blob/Manifest/Evidence SHA-256, Manifest↔Raw 매핑, 복제본 바이트를 재검증한다.

| 상황 | 동작 |
| --- | --- |
| SQS 중복/재전달 | 객체 advisory lock 후 Receipt 확인 → 보존본 검증 → 건너뜀 (Run 중복 없음) |
| Worker 재시작·중간 종료 | 단일 트랜잭션이라 부분 커밋 없음. 재전달 시 처음부터 다시 처리 |
| 보존 성공 / DB 실패 | 복제본 파일만 남을 수 있음(콘텐츠 주소, 무해). 재시도 시 같은 바이트면 그대로 사용 |
| DB 성공 / 복제본 확인 실패 | 조회에 `degraded` + 사유를 표시하고 `raw_verified`로 표시하지 않음. 재전달 때 누락 파일만 재게시(`repaired`) |
| 같은 S3 identity, 다른 콘텐츠 | `upload_content_sha256_mismatch` 등 → Permanent, Run 미생성 |
| 해시 충돌·불일치 | 해시 일치 후에도 전체 바이트 비교. 다르면 `raw_content_hash_collision` |
| 복제본 파일 유실 | 누락만 DB 정본에서 재게시. 내용이 다른 파일은 덮어쓰지 않고 `archive_mirror_content_conflict` |
| 권한 오류 | `archive_mirror_write_failed` → 롤백, 부분 파일 없음(같은 디렉터리 임시파일 + fsync + hardlink) |
| Retention 이전 Receipt (006/007/008 유형) | 건너뛰고 `degraded`/`receipt_without_raw_archive` 감사. backfill·승격 없음 |

복제본 경로는 코드가 생성한 구성요소(검증된 Run ID, hex digest)만 쓴다. 루트 아래 symlink와
junction은 거부한다. Windows에서 `resolve()`가 경쟁 상태일 때 `\\?\` 경로를 반환하던 오판도
제거했다.

## 5. 원본 검증과 승격 조건

`raw_verified`는 다음을 **모두** 통과할 때만 부여한다.

FusionResult 기여 ID → 보존된 생성 시점 Evidence(Run/Entity/ID/Extractor) → 정확한 Event ID·Run·Host·
시각·Source layer → `raw_ref`의 raw_log_id/segment → 같은 Run의 보존 Manifest(run_id, source/layer,
SHA-256) → Raw SHA-256 → `record_no` 위치의 레코드 → `RecordId == source_event_id`
→ Parser v0.3로 다시 정규화한 Event 전체 == 저장 Event (Process/Network 필드 포함).

하나라도 실패하면 `event_verified`(Event 연결만 확인) 또는 `unresolved`(보존본 자체 불일치)로
남기고 code-owned 사유를 반환한다. Dashboard는 이를 한국어로 표시한다. Extractor 코드가 이후 바뀌어도
보존된 원본 Evidence의 연결 검증은 유지된다. 코드 해시 차이는 따로 표시하고, 관측 문장은 현재 규칙이
같은 Evidence를 재현할 때만 만든다.

## 6. 격리 E2E 결과

새 LocalStack 컨테이너(4577, 종료 후 삭제)와 새 소유 marker DB(`modeling-postgres-1`)를 사용했다.
Dashboard는 8811, Worker는 `python -m incident_awareness.pipeline.sqs_worker --once`를 매번 새
프로세스로 실행했다. 기존 데모 스택, 8794~8808 서버, 운영 원장은 사용하지 않았다.
절차와 증적은 `build/raw-artifact-retention/e2e/`에 있다.

| 단계 | 결과 |
| --- | --- |
| Dashboard UI 업로드 | Attack/Normal 202, `upload_prepared → uploaded`, S3 메타 `content-sha256` = 원본, ETag ≠ SHA-256 |
| Worker 처리 | Attack `RUN-20261020-001`, Normal `RUN-20261020-002`, 저장 Event 869/884 |
| Attack Provenance | 기여 Evidence 2건 모두 `raw_verified`, `retained_archive`, 코드 해시 일치 |
| Normal | Raw 보존 검증됨, 기여 Evidence 0건, 관측 문장 0건 |
| LocalStack 재시작 | S3 객체 404, Dashboard 재시작 후 검증 결과 해시 동일 |
| 복제본 파일 삭제 중 | `degraded`/`archive_mirror_missing`, 2건 `event_verified` (승격 안 함) |
| 재전달 + 새 Worker | `skipped`, Run/Receipt 수 불변, 복제본 `repaired` → 다시 `raw_verified` |

Attack Evidence:

| Evidence | 유형 | Source Event / record_no | 관측 (UTC) |
| --- | --- | --- | --- |
| `E-fc87ff49-aa10-566e-ba75-e78d5679017b` | encoded_powershell_command | 7732 / 14 | 2026-09-27T07:49:41.358Z |
| `E-e8e077bb-6b82-5474-985d-bcef4b8f43b8` | script_interpreter_external_connection | 7899 / 181 | 2026-09-27T07:51:42.089Z |

Manifest identity는 `raw-manifest:RUN-20261020-001:sha256:0242ff1f…c6bc`, Raw SHA-256은 `78c4b4a2…6d8da`다.
7732/7899와 14/181은 007 저장 Event의 Source Event ID·record_no와 같다. 이 신규 Run은 007과
별개의 Run이다. 따라서 이 결과를 007의 원본 증적으로 사용하지 않으며 007의 상태도 바꾸지 않는다.

## 7. Grounded Report와 DOCX

새 Run의 Workflow는 격리 DB의 **TEST FIXTURE** 행위(확인·근거 검토·보고 진행)로만 진행했다.

- 보고서 초안 v1에 `verified_observations` 2건이 들어갔다. 6개 필드(원인·피해·조치 등)는 `UNKNOWN`을
  유지하고, 외부 LLM 요청은 0건(`requested_at = null`)이다.
- KISA 양식(그 밖의 해킹)의 사고내용은 다음과 같다. "개발용 침해 의심 사례입니다. 실제 사고·피해는
  확정되지 않았습니다."에 이어 공인 IP `1.1.1.1:443` 연결 관측(악성 여부 미확인)과 인코딩된
  PowerShell 실행 옵션 `-encodedcommand` 관측이 들어간다. 사고발생시간은 확인불가, 인지시점은
  미기록이다.
- DOCX(`9c688e8e…`)는 브라우저 다운로드와 API 해시가 같다. Word 16.0 네이티브 검증을 통과했다
  (3페이지, 원본 불변, 편집 사본 재열기, PDF 미생성). 감염·유출·공격 성공·C2·피해 규모 표현과
  인코딩 payload 원문은 없다.

기존 ReportDraft와 DOCX는 덮어쓰지 않는다. 보고서 원장은 E2E 전용 SQLite를 사용했다.

## 8. 노출 정책

브라우저에는 Raw 본문을 보내지 않는다. Provenance 응답의 `source_events`는 ID/시각/유형/
raw_ref만 담는다. 보고서 조회는 `process`/`network`/`user`를 제거한다. 관측 문장에는 원문 명령줄,
사용자, 출발지 내부 IP가 없다. 원본 바이트(명령줄 포함)는 PostgreSQL에만 있으므로 DB 접근
권한이 곧 원문 열람 권한이다.

## 9. Migration 리허설과 실제 데모 적용

2026-10-21 사용자 명시 승인 후 **로컬 데모 54330에 015만 적용**했고 Worker 한 서비스 교체,
8812 Dashboard 및 신규 Attack/Normal 입력 검증을 수행했다.
아래는 승인 전 리허설과 적용 계획 기록이다.

리허설은 새 소유 DB에서 수행했다(`build/raw-artifact-retention/migration-rehearsal.json`).
014 상태 DB와 기존형 Run → `pg_dump -Fc` 백업 → 별도 DB 복원(동일) → 015 적용(기존 행·스키마·함수
불변) → 롤백(015 이전과 완전 동일) → 재적용 후 신규 Run `raw_verified` 2건, 기존형 Run은
`event_verified` 2건과 `unavailable`, TRUNCATE 거부까지 확인했다.

LocalStack 데모 DB(54330)에 적용하려면 별도 승인을 받은 뒤 다음 순서로 진행한다.

1. `pg_dump -Fc`로 백업하고, 소유 DB에 복원해 검증한다.
2. **전체 Migration CLI를 실행하지 않는다.** 실제 54330 DB는 013/014만 registry에 등록되어 있고
   001~012 스키마는 이미 존재한다. 승인 후 `_apply_migration_paths(connection, (migration_015_path,))`로
   015만 적용한다. initdb 마운트는 기존 volume에 다시 실행되지 않는다.
3. 기존 테이블 스냅샷을 비교한다.
4. Worker 이미지를 이 코드로 재빌드하고 Dashboard·Worker에 `IAE_RAW_RETENTION_ENABLED=1`을 설정한다.
   Compose 변경과 Worker 재시작이 필요하다.

롤백(보존 데이터가 생기기 전):

```sql
DROP TABLE raw_archive_audit;
DROP TABLE raw_run_archives;
DROP TABLE raw_artifact_blobs;
DROP FUNCTION guard_raw_archive_immutable();
DELETE FROM schema_migrations WHERE migration_id = '015_raw_artifact_retention';
```

위 SQL은 **보존 데이터가 전혀 없는 격리 DB 리허설**에만 사용했다. 기존 데모에 자동 실행하지 않는다.
신규 보존 데이터가 생긴 뒤에는 테이블을 제거하거나 구버전 Worker로 자동 복귀하지 않는다.
업로드·Worker 처리를 통제하고 신규 데이터까지 백업한 뒤 복구 영향과 별도 승인을 확인한다.
원본 DB 복원은 이후 Run·감사기록을 되돌릴 수 있으므로 별도 승인 없이는 수행하지 않는다.

2026-10-21 실제 데모 백업·복원 및 승인 전 점검을 마쳤다. 원본 015 적용과 Worker 교체는
승인 게이트를 통과한 뒤 실행했으며, 원본 DB 전체 복원이나 LocalStack/PG 재시작은 하지 않았다.

## 10. 남은 한계

- 무결성의 기준점은 PostgreSQL이다. DB 관리자가 SQL 제약을 만족하도록 일관되게 다시 쓰면 해시만으로는
  탐지할 수 없다. 레코드 내용이 바뀌면 저장 Event와의 불일치로 검출된다. 외부 앵커·서명·WORM은 없다.
- 검증 범위는 보존된 Sysmon JSONL이며 EVTX 진위가 아니다. Standalone Manifest의 EVTX 항목은
  placeholder다. 지원 범위는 S0 Sysmon JSONL, segment 1, Parser v0.3이다.
- 보존 기간과 정리(GC) 정책은 없다(append-only). 운영 전 용량과 보존 기간을 정해야 한다.
- 실제 Run의 외부 LLM 전송, 운영 DB 적용, KISA 제출은 하지 않았다.
