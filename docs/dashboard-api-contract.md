# 대시보드 조회 API 계약 v1 — 구현 기준 제안

범위: Overview / Runs / Run Detail의 읽기 API. 공통 DetectionResult 등의 정본을 변경하지 않는 화면용 read model이다. Run 목록·상세 API는 구현했으며, Overview 집계와 Runs·Run Detail 화면도 구현했다. Report 저장·LLM API는 별도 계약이다.

## 공통

- 모든 응답 시각은 timezone 포함 UTC ISO 8601. 판단 시각은 정본의 밀리초 정밀도 유지. 화면에서 Asia/Seoul로 변환하고 KST (UTC+9) 표시.
- 인증된 backend를 통해 조회. SQL parameter binding 및 리소스 접근 권한 검사. 브라우저의 RDS 직접 연결 금지.
- null은 계약상 값 없음이며 빈 문자열이나 0으로 치환하지 않는다.
- detected=탐지, miss=미탐지, not_evaluated=미평가. 결과 행 없음은 별도 availability=missing. API 오류를 탐지 상태로 저장하지 않는다.
- decision_path=탐지 경로, winning_path=최초 탐지 경로, t_e=시스템 판단 시각. tie=동시 탐지. none과 null 구분.
- run_type은 실험 정답 라벨이다. 운영 판정이나 LLM 사고 판단의 근거로 전달하지 않는다.
- 아래 모든 nullable 필드는 키를 생략하지 않는다. API 설계 필드는 DB 컬럼이 아니다.

## GET /api/runs

query: limit(기본20,1~100), offset(기본0,0이상). 초기 구현은 페이지 이동 중 실시간 변경으로 인한 중복/이동 가능성을 명시하며 고정 snapshot이라고 주장하지 않는다.
정렬: runs.start_time DESC, runs.run_id DESC.
한 item은 한 Run. total은 같은 권한 범위의 runs 행 수이며 JOIN으로 늘리지 않는다.
latest_decision은 해당 Run 전체에서 created_at DESC, decision_id DESC로 선택한 한 Decision이다. 대표 entity의 판정이나 Run-level reduction을 의미하지 않는다.

응답:
- items: RunListItem[]
- total: integer >=0
- limit: integer
- offset: integer

RunListItem:
- run_id, scenario_id, target_host: string
- run_type: normal | attack
- start_time: UTC datetime
- end_time: UTC datetime | null
- has_decision: boolean (latest_decision != null과 반드시 일치)
- latest_decision: DecisionSummary | null

DecisionSummary:
- decision_id, entity_id: string
- created_at: UTC datetime (저장 시각)
- fast_status, fusion_status: detected | miss | not_evaluated
- detector_time, fusion_time, t_e: UTC datetime | null
- decision_path: fast | fusion | fast_and_fusion | none | null
- winning_path: fast | fusion | tie | none | null
- config_version: string
- detector_set_version, supersedes_decision_id: string | null

Overview에서 상태 집계가 필요하면 페이지 items만 합산하지 않는다. 별도 전체 범위 집계 API를 추가하며 집계 단위를 'Run별 최근 저장 Decision'으로 명시한다.

## GET /api/runs/{run_id}

query: decision_id(optional), event_limit(기본50,1~200), event_offset(기본0,0이상).
명시된 decision_id는 반드시 요청 run_id에 속해야 한다. 없으면 created_at DESC, decision_id DESC의 첫 Decision. 해당 Run에 Decision이 없으면 selected_decision=null로 200 반환.
Run 자체가 없거나 요청 Decision이 없거나 다른 Run 소속이면 404. 잘못된 query는 400. 인증 실패401, 권한 거부403, DB 등 서버 오류503(원문 SQL/비밀값 비노출).
한 응답의 metadata, decision 및 결과 조회는 같은 read-only DB snapshot 사용.

응답 필드:
- run: {run_id, scenario_id, run_type, target_host, start_time, end_time}
- selected_decision: DecisionDetail | null
- current_entity_results: CurrentEntityResults | null
- evidence: {ids: string[], availability: ids_only | not_available}
- events: {items: EventSummary[], total: integer, limit: integer, offset: integer}
- timeline: {items: TimelineItem[], event_scope: returned_page, total_event_count: integer}

DecisionDetail: DecisionSummary 필드 + decision_reason:string, contributing_evidence_ids:string[]|null, source_hit_ids:string[]|null, selected_source_hit_id:string|null, model_version:string|null, rule_version:string|null.
저장된 Decision payload의 값을 사용하며 UI에서 t_e/경로를 다시 계산하지 않는다.

CurrentEntityResults:
- entity_id: selected_decision.entity_id
- relation_to_selected_decision: unverified
- fast: {availability: available | missing, value: FastDetail | null}
- fusion: {availability: available | missing, value: FusionDetail | null}

FastDetail: detector_status, detector_time, detector_id, rule_id, rule_version, severity (정본 타입/nullable 유지).
FusionDetail: fusion_status, fusion_time, score_at_decision, model_version, scoring_config_version, scoring_method, contributing_evidence_ids, fusion_episodes (정본 타입/nullable 유지).

중요: 현재 Fast/Fusion 테이블은 (run_id,entity_id) upsert다. 가장 최근 Decision이어도 상세가 같은 실행에서 생성됐다고 보장되지 않는다. 위 상세는 '현재 저장된 경로 결과—선택 Decision과 실행 일치 미확인'으로 별도 표시하고, 선택 Decision의 근거/타임라인/LLM 입력에 혼합하지 않는다. 불변 snapshot 또는 result version 연결이 구현되면 verified 관계를 별도 계약으로 추가한다. 최종본에서 과거 판정의 상세 재현을 보장하려면 이 저장 확장이 필요하다.
Decision이 없으면 current_entity_results=null; target_host를 임의 entity 매핑으로 사용하지 않는다.

Evidence: selected_decision.contributing_evidence_ids를 표시한다. null은 not_available, 빈 배열은 ids_only와 []로 표현. ID 존재가 본문 조회 가능을 뜻하지 않는다. Event를 시각이나 host만으로 Evidence와 연결하지 않는다.

EventSummary: event_id, timestamp, host_id, event_type. payload는 목록 응답에 포함하지 않고 별도 상세 API에서 허용 필드를 조회한다.
이벤트 목록은 Run 전체이며 각 행 host_id를 표시. 정렬 timestamp ASC,event_id ASC. total은 반환 페이지 건수가 아닌 전체 Run 이벤트 수.

TimelineItem: {key:string, kind:run_start|event|fast_detection|fusion_detection|system_decision|run_end, timestamp:UTC datetime, source_id:string}.
Run 시작/종료 + 선택 Decision의 detector_time/fusion_time/t_e + 반환된 Event 페이지를 사용한다. null 시각은 항목을 만들지 않는다. timestamp ASC,key ASC로 안정 정렬. 페이지 일부 이벤트임을 명시한다. 시각이 같아도 항목을 유실하지 않고 화면에서 그룹화할 수 있다. 담당자 인지시각/DB 저장 시각으로 해석하지 않는다. 연결이 검증되지 않은 현재 Fusion episode는 이 타임라인에 섞지 않는다.

## 이력·이벤트 상세 후속 API

- GET /api/runs/{run_id}/decisions?limit=20&offset=0: DecisionSummary 목록, created_at DESC,decision_id DESC. total 포함. supersedes_decision_id는 실제 저장 링크만 표시하며 단순 시간순을 대체 관계로 추론하지 않는다.
- GET /api/runs/{run_id}/events/{event_id}: Run 소속 검사 및 서버 측 허용 필드 필터 적용. raw payload 전체/비밀값을 그대로 노출하지 않는다.
- Report 저장/수정/LLM 및 불변 결과 snapshot은 최종본에 필요한 별도 작업이며 이 두 조회 API만으로 대시보드 최종 완성을 주장하지 않는다.

## HTTP 오류 응답

{"error":{"code":"RUN_NOT_FOUND","message":"Run을 찾을 수 없습니다."}}
code는 INVALID_QUERY / RUN_NOT_FOUND / DECISION_NOT_FOUND / UNAUTHORIZED / FORBIDDEN / DATA_SOURCE_UNAVAILABLE 등을 사용한다. 오류 응답과 성공 JSON을 혼합하지 않는다.

## 조회 API 실행 (이번 구현)

`incident_awareness.dashboard.app:app`에서 목록·상세 조회를 제공합니다.

```bash
# 서버 환경에 INCIDENT_AWARENESS_DATABASE_URL과 INCIDENT_DASHBOARD_TOKEN 설정 후
PYTHONPATH=src uv run uvicorn incident_awareness.dashboard.app:app --host 127.0.0.1 --port 8000
```

요청은 `Authorization: Bearer <토큰>`을 사용합니다. 토큰을 프론트 소스나 저장소에
저장하지 않습니다. 현재 권한 범위는 한 프로젝트의 운영자 그룹 전체 Run 조회입니다.
사용자별/조직별 권한 분리가 필요한 배포에는 별도 인증 연동이 필요합니다.
외부 노출 시 HTTPS와 인증 프록시를 적용해야 합니다.

DB 조회는 요청별 read-only/repeatable-read 트랜잭션이며 SQL 실행 제한은 5초입니다.
페이지 크기는 Run 최대 100개, Event 최대 200개입니다. 응답은 캐시하지 않습니다.
DB 연결 오류 및 저장된 결과의 계약 위반은 세부 접속정보 없이 503으로 반환합니다.

이번 구현은 `GET /api/runs`와 `GET /api/runs/{run_id}`입니다.
Decision 이력 목록, Event 상세, Report 생성·수정 API는
후속 구현 대상입니다. 현재 결과와 과거 Decision의 연관성은 `unverified`로 유지합니다.

## Overview 전체 집계

`GET /api/overview`는 인증된 운영자 범위의 전체 Run을 집계합니다. 페이지나 날짜
필터는 적용하지 않습니다. 동일 read-only/repeatable-read 트랜잭션에서 읽습니다.

- `scope`: `all_runs`
- `decision_basis`: `latest_per_run`
- `total_runs`, `runs_with_decision`, `runs_without_decision`, `total_events`: 정수
- `fast`, `fusion`: `detected / miss / not_evaluated / missing`별 Run 수
- `decision_paths`: `fast / fusion / fast_and_fusion / none / not_evaluated / missing`별 Run 수

최신 Decision은 목록 API와 같은 `created_at DESC, decision_id DESC` 순서입니다.
Decision 없는 Run은 `missing`, Decision의 null 경로는 `not_evaluated`로 집계합니다.
`none`은 양쪽 미탐지에 대응하며 null 경로와 구분합니다. 빈 DB는 모든 건수가 0입니다.
여러 entity의 Run 단위 통합 판정이 아니며 Recall·FPR·FA/BH를 의미하지 않습니다.
과거 Decision과 현재 Fast/Fusion upsert 결과를 결합해서 집계하지 않습니다.
