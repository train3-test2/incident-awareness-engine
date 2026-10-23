# KISIA AI보안 프로젝트 — 최종 Dashboard 설계 및 개발 결정

결정일: 2026-10-21, Asia/Seoul\
대상: Train 3 Test 2 / incident-awareness-engine\
일정: 10월 23일 내부평가 영상 제출, 11월 5일 외부평가\
문서 성격: 구현 착수 기준. 아래의 신규 설계는 구현 완료 보고가 아니다.

## A. 최종 판정

**판정: 조건부 수정. B안을 채택한다. 기존 운영 Dashboard를 유지하면서 실시간 관측을 동일 목록·상세 화면에 수용하고, 관측·정식 분석·담당자 결정을 서로 다른 상태로 표현한다.**

별도 R1 시연 카드와 별도 사이트는 만들지 않는다. 전체 프런트엔드 재작성도 하지 않는다. 기존 사건 요약·증거 조회·담당자 처리·Word 생성기를 재사용한다. 다만 임시 규칙 결과를 정식 분석 결과처럼 넣는 ‘데이터 그대로 입력’ 방식은 기각한다. **표시용 읽기 모델에서 통합하고, 원천 결과와 저장 계약은 분리한다.**

### A-1. 이번 검토에서 실제로 확인한 범위

| 구분 | 확인 내용 | 해석 및 한계 |
|---|---|---|
| 로컬 소스 확인 | 브랜치 `feature/dashboard/demo-polish`, HEAD `e058a12`; Dashboard·Workflow·신고서·원본 검증 관련 다수 수정 및 미추적 파일 존재 | HEAD만으로 실행 코드를 재현할 수 없다. 미커밋 변경까지 보존해야 한다 |
| 원격 확인 | GitHub `develop` 조회 SHA `033ea8579cc42ff30ed6927e8e02ab2c3f563e52` | 검토 시점의 값이며 이후 변경 가능 |
| 로컬 추적 참조 | `origin/develop`은 `7c7727b`; HEAD와 비교 시 로컬 전용 10개/추적 참조 전용 39개 커밋 | 로컬 추적 참조도 최신 원격과 다르다. 최신 원격과의 정확한 충돌 목록은 미검증 |
| PR #302 | 병합 완료, merge SHA `cdfb6d04fc4fa19ec62d67b4e8d77606cd941ff8`; 생산자·spool·commit 후 ACK 구현 확인 | PR 설명상 당시 실제 VM 검증 미수행. source completeness 부재로 final watermark/close 자동 발급 금지 |
| 로컬 #302 반영 상태 | 현재 작업 트리에 `r1_stream_wiring.py`, `r1-incremental-sysmon-producer.ps1` 없음 | 현재 로컬 Dashboard와 #302가 이미 통합됐다고 볼 수 없다 |
| 화면 확인 | `build/operator-ui-redesign/after/overview-1920.png` 직접 확인, 해당 HTML/JS 읽음 | 저장된 화면 자료다. 현재 브라우저의 모든 동작을 재실행한 결과는 아니다 |
| 실행 서버 읽기 확인 | 8815·8816 `/healthz` HTTP 200, 두 서버의 Workflow GET 응답 확인 | healthz는 프로세스 응답일 뿐 전체 수집·DB·모델 정상 증거가 아니다. 두 서버의 Run 집합이 다름 |
| 이번 재실행 | Python 41개, Node 43개 관련 기존 테스트 통과 | Workflow·승인 스냅샷·runtime-context 및 UI 계약 범위. 실제 VM·실제 Claude·PostgreSQL 전체 E2E 재실행 아님 |
| 기존 실증 기록 확인 | `build/approved-llm-report/REPORT.md`: 합성 Sysmon Run 901 → 실제 S0 처리 → 실제 Claude → 검증 → Word → 재시작 복원 기록 | 기존 기록을 확인한 것. 실시간 R1에서 같은 연결이 성공했다는 증거가 아니다 |
| 미확인 | 최신 원격 전체 회귀, 촬영 VM 상태, 실시간 R1의 canonical 연결, R1 서술 지원, 배포 서버별 코드·migration 일치 | 구현 착수·촬영 승인 조건으로 남긴다 |

PR 근거: [PR #302](https://github.com/train3-test2/incident-awareness-engine/pull/302), [commit 후 ACK 구현](https://github.com/train3-test2/incident-awareness-engine/blob/cdfb6d04fc4fa19ec62d67b4e8d77606cd941ff8/src/incident_awareness/pipeline/r1_stream_wiring.py#L246).

### A-2. 반드시 수정할 결함

1. **알림 생성의 브라우저 의존성.** 현재 `dashboard-workflow-controller.mjs`의 Run 선택은 `POST /human-workflow/runs/{run_id}/sync`를 호출한다. 독립 분석 Worker는 있지만, 이 화면 경로로 만들어지는 알림의 `issued_at`은 실제 분석 완료보다 늦을 수 있다. 서버의 독립 조정 작업으로 생성하고 화면 조회는 GET으로 바꾼다.
2. **로그인과 데모 담당자의 혼동.** 현재 `local_actor`와 DB CHECK는 `local-demo-analyst`/`unauthenticated_local_demo`를 강제한다. 로그인 UI만 추가해서 운영 인증으로 표현할 수 없다. 10월 23일은 ‘통제 실험 환경 · 로컬 담당자’로 명시한다.
3. **분석 경로의 잘못된 직렬 표현.** 기존 6칸은 실행 계측 순서를 보여주며 Fusion 다음에 Fast가 오는 것으로 읽힌다. 논리 분석 경로를 두 갈래로 바꾸되, 실제 실행되지 않은 Fast를 활성화하지 않는다. 현재 standalone은 Fast를 명시적으로 `not_evaluated`로 만든다.
4. **임시 규칙과 정식 결과의 저장 혼용.** `DEMO_RULE_MATCH`를 `FusionResult`, `DecisionResult`, `t_e`로 변환하지 않는다. 현재 Workflow 테이블도 `detection_kind IN ('fusion','hybrid')`만 허용하므로 규칙 결과를 기존 타입으로 위장해서 넣을 수 없다.
5. **계측의 의미 확대.** 기존 telemetry는 실행 시도별, 정규화·증거 처리 구간의 측정값이다. 이를 수집 전체 처리량·종단 지연·탐지 시간·TTSD로 표시하지 않는다.
6. **‘인지시각’과 ‘기록시각’의 혼동.** 단계 타임라인의 ‘인지 기록 완료’는 `t_h_recorded_at`, 사용자가 정한 인지시각은 `t_h`로 별도 표시한다. 현재 표시 함수는 인지 기록 단계에 `t_h`를 넣는다.
7. **기능 버전과 데이터 출처 혼동.** 서버 주소·코드·DB·신고서 SQLite·artifact root를 하나의 실행 manifest로 묶는다. 8815와 8816 사이를 같은 사건의 연속 화면처럼 오가지 않는다.

### A-3. 동일 시각 문제의 확인 결과

8816에서 읽은 `RUN-20261021-901`의 2026-10-21 UTC 값:

| 항목 | 저장된 시각 |
|---|---|
| 알림 발행 | 04:47:24.084884 |
| 담당자 확인 | 04:47:24.559152 |
| 근거 검토 | 04:47:24.655230 |
| 내부 인지시각 | 04:47:24.708 |
| 인지시각 기록 | 04:47:24.708 |

이 사례는 저장값이 같지 않다. 동일 초에 여러 동작이 발생했고 UI `toLocaleString`이 소수초를 생략한다. 기존 자동화 시연 기록과 부합하지만, 다른 모든 Run의 원인까지 확정하지 않는다. `now`로 기록한 `t_h`와 `t_h_recorded_at`이 같은 것은 정상이다.

8815의 `RUN-20261019-007`은 근거 검토가 확인보다 먼저 기록됐고 `t_h`가 null이다. 신고 결정은 존재한다. **신고 결정을 근거로 인지 기록을 완료 처리하면 안 된다.** 기존 기록은 수정하지 않고 사실대로 보여준다.

### A-4. 이번 일정에서 줄일 요구

P0에서 새 차트, 전체 로그인/RBAC, 이메일·문자·메신저, 모바일 전체 업무, SSE/WebSocket, 새 프런트엔드 프레임워크, LLM 운영 인사이트, 자동 신고 제출을 제외한다. 빠진 계측값을 채우기 위한 가짜 uptime·진행률·위험 점수도 제외한다. 새 알고리즘이나 모델 교체로 범위를 넓히지 않는다.

## B. 최종 Dashboard 제품 방향

**제품 목적은 ‘관측된 침해 의심 신호에서 검증 가능한 근거와 사람의 대응 기록, 검토용 신고서까지 연결하는 업무 화면’이다.** 주요 사용자는 관제 분석가와 사고 대응 담당자이며 관리자는 처리 누락과 근거·기록을 확인한다.

### B-1. 화면 구조와 정보 경계

| 운영자에게 기본 노출 | 기술 상세에 보존 | 평가 화면에만 노출 |
|---|---|---|
| 사건/관측 식별자, 대상 시스템, 데이터 출처, 최신성 | Run·execution·partition ID, 원본 참조, 해시 | Attack/Normal ground truth, 학습/검증 분할 |
| ‘규칙 기반 의심 관측’, ‘증거 누적 분석’, ‘통합 판단’ | `DEMO_RULE_MATCH`, Fast/Fusion/Hybrid 원천 상태 | TTSD 적격 여부와 정식 평가 방법 |
| 관측 사실, 검증 완료/대기/실패, 다음 행동 | selector/policy/config 버전, ACK·ledger 결속 | 모델별 성능, 실험 비교 |
| 담당자 처리 상태와 시각, 신고서 버전 | 감사 원장·멱등 키·정정 전후 값 | 원본 실행 명령·수집 실험 메타데이터 |

‘통제 실험 데이터’, ‘합성 입력’, ‘사후 분석’, ‘규칙 관측 · 정식 분석 미수행’은 의미에 영향을 주므로 접힌 영역에만 숨기지 않는다. R1/Demo라는 내부 명칭은 줄여도 검증 한계는 기본 화면에 남긴다.

### B-2. 공통 화면에서 유지할 네 가지 독립 축

1. **출처:** 통제 VM 실제 수집 / 합성 입력 / 운영 수집. 마지막 분류는 실제 운영 배포가 확인된 경우에만 사용.
2. **처리:** 관측 중 / 실행 중 / 완료 / 실패 / 상태 미확인. 완료는 침해 판정이 아니다.
3. **판단·검증:** 규칙 의심 / 조건 미충족 / 정식 분석 탐지 / 미탐지 / 미평가; 원본 검증과 전체 수집 완전성은 별도.
4. **담당자 업무:** 미확인 / 확인 / 검토 / 인지 기록 / 신고 결정 / 초안 검토. 기계 결과에서 자동 유도하지 않는다.

하나의 빨강·초록 배지로 네 축을 합치지 않는다. 규칙 일치는 주황색 ‘검토 필요’, 실제 정식 탐지에는 붉은 강조를 사용할 수 있다. `RULE_NOT_MATCHED`는 ‘현재 관측 범위에서 조건 미충족’이며 ‘정상’이나 ‘안전’이 아니다.

### B-3. UI 원칙

현재 운영 화면의 골격과 컴포넌트 ID를 유지한다. 첫 화면은 미처리 업무·최근 관측·선택한 사건의 다음 행동을 우선한다. 점수 추이는 상세 탭에 유지한다. 데이터가 없는 차트는 작은 상태 영역으로 축소한다.

사용 중인 사건과 입력 폼을 새 사건 때문에 자동 변경하지 않는다. 상단 처리 현황의 최신 실행 자동 추적은 선택 사건과 분리한다. 새 항목은 ‘새 관측 N건’ 버튼으로 알리고, 사용자가 열거나 목록을 갱신하게 한다.

데스크톱 1366·1920px를 P0 기준으로 한다. 1024px 이하에서는 단일 열, 표만 가로 스크롤한다. 좁은 화면에서 기록·다운로드 버튼이 잘리지 않게 하되 모바일 전용 전체 업무는 P2다. 상태는 색상과 텍스트·아이콘을 함께 쓰고 키보드 포커스와 `prefers-reduced-motion`을 지원한다.

## C. 최종 화면 설계

### C-1. 영역별 계약

| 화면/영역 | 표시 데이터와 실제 출처 | 갱신 | 사용자 상호작용 | 로딩·대기·오류·미확인 | 우선순위 |
|---|---|---|---|---|---|
| 상단 환경·연결 | 배포 manifest, API 응답, 서버 시각, 데이터 마지막 갱신 | Live 1초, 기존 runtime 5초 | 표시 기준 펼치기 | API 연결 실패와 수집 상태 미확인을 분리 | P0 |
| 운영 요약 | `/operations/runtime-context`, `/overview`; 이후 범위 있는 집계 API | 5초 | 실행/오류 목록 열기 | 조회된 5건을 전체 운영 건수로 쓰지 않음; 미계측 uptime은 숨김 | P0 |
| 최근 분석·관측 | 기존 `/runs`·runtime + 신규 Live 읽기 모델 | Live 1초, 기존 5초 및 주기적 목록 재조회 | 필터, 항목 선택, 새 항목 보기 | 미수신·진행·실패 구분, 다른 source ID 충돌 차단 | P0 |
| 분석 처리 현황 | 선택 범위의 stage timings, Live 단계 사실 | 각 원천 주기 | 최신 실행/선택 항목 전환 | 완료 증거 없음은 unknown; 미지원과 대기 구별 | P0 |
| 관측/사건 요약 | Live 계보·연결, 또는 저장 Fusion/Decision snapshot | 원천 revision 변경 시 | 관측 사실 열기 | 정식 결과 없음은 미수행. 관측 ID와 정식 사건 ID 관계 명시 | P0 |
| 근거·원본 검증 | 기존 evidences/provenance API, 사후 archive 검증 결과 | 선택·명시 갱신·결과 revision 변경 | 출처/관련 이벤트 조회 | source completeness unknown과 개별 raw 검증 완료가 공존 가능 | P0 |
| 알림 영역 | 저장 Live match journal 및 정식 Workflow 알림 | Live 1초, 정식 5초 | 사건 보기; 닫기; 정식 알림의 명시적 확인 | 닫기는 확인 기록 아님. 장애 후 다시 조회 | P0 |
| 담당자 처리 | 기존 Workflow GET/actions, audit | 선택 시·저장 후·활성 사건 5초 | 확인·검토·인지·신고 결정 | 저장 중 중복 클릭 차단, 충돌·저장 실패 표시 | P0 재사용 |
| 신고서 | ReportDraftStore·KISAFormStore, 승인 snapshot API | 생성/조회/다운로드 시 | 유형 선택, 요청 확인, 초안 검토, Word 다운로드 | AI 실패와 대체 작성, Word 생성 실패를 분리 | P0 재사용 |
| 운영 인사이트 | 검증된 runtime/telemetry/알림 집계의 결정 규칙 | 5초 | 근거 수치·기간 열기 | 모집단/기간이 없으면 ‘증가’ 추정 금지 | P1; 기존 실측 항목 유지 |
| 처리량·처리 시간 | `/operations/telemetry`의 실제 points | 기존 5초 | 범위·실행 선택 | null은 미관측; 측정된 0만 0으로 표시 | P1 확장; 기존 차트 유지 |
| 기술·평가 상세 | 기존 진단·평가 API, 실행 manifest | 명시 조회 | 로그·버전·평가 확인 | 운영 표시와 다른 데이터 범위를 제목에 명시 | P0 기존 재사용 |

### C-2. 텍스트 Wireframe

```text
┌ 운영 현황 | 사건·관측 | 평가 | 시스템 상태 ─ 통제 실험 환경 · 로컬 담당자 ┐
│ API 연결: 확인됨    수집 보고: 1초 전    분석 보고: 4초 전               │
├───────────────────────────────────────────────────────────────────────┤
│ [현재 분석] [조회 범위 내 완료] [정식 미확인 알림] [규칙 의심 관측]       │
│ 집계 미구현 값은 표시하지 않음 / 가동 시간 미계측 카드 제거              │
├───────────────────────────────────────────┬───────────────────────────┤
│ 최근 분석·관측                     [새 1건]│ 선택 항목: 관측 O-…       │
│ 시각 | 대상 | 관측/분석 | 검증 | 처리      │ 규칙 기반 의심 관측       │
│ …   | A    | 규칙 의심 | 사후 대기 | …     │ 통제 VM 실제 수집         │
│ …   | B    | 누적 탐지 | 원본 검증 | 검토  │ 정식 분석: 미수행         │
│                                           │ [관측 사실 보기]          │
├───────────────────────────────────────────┴───────────────────────────┤
│ 처리 현황 [선택 항목 / 최신 실행]                                      │
│ 경로에 해당하는 단계만 표시; 선택 범위·마지막 보고 시각 표시              │
├───────────────────────────────────────────────────────────────────────┤
│ 요약 | 근거 | 담당자 처리 | 판단 이력 | 점수 추이                       │
│ 정식 사건 선택 시: [다음 행동] [내부 대응 목표까지 …]                    │
│ 인지시각: …   기록시각: …   ▶ 감사 이력                                │
├───────────────────────────────────────────────────────────────────────┤
│ 실측 처리량/처리 시간 (데이터 있을 때) | 수치 기반 운영 요약              │
└───────────────────────────────────────────────────────────────────────┘
```

### C-3. 처리 단계 표현

정식 분석의 **논리 경로**:

```text
수집·입력 검증 → 정규화 ┬→ 즉시 규칙 분석(Fast) ───────────┐
                       └→ 증거 처리 → 누적 분석(Fusion) ─┤
                                                        ↓
                                                  통합 판단 → 결과 저장 → 알림 저장
```

Fast/Fusion 사이에 선후 의존 화살표를 놓지 않는다. 다만 현재 standalone은 Fusion 실행 후 미실행 Fast 결과를 결합하는 코드이므로, 두 갈래가 동시에 실행 중이라는 애니메이션을 만들지 않는다. 논리 경로와 실제 stage timing 목록을 구분한다. `HYBRID` 단계 실행 완료도 ‘통합 판단이 탐지했다’는 뜻은 아니다.

Live 규칙 경로:

```text
이벤트 수신·정규화 → 수락 확인 → 계보·연결 관측 → 규칙 관측 기록 → 화면 알림
                                                    └→ 사후 원본·증거 검증 대기
정식 분석: 이 경로에서 미수행
```

단계 공통 상태는 `pending / running / completed / failed / not_applicable / not_implemented / unknown`으로 정한다. 원천에 단계 시작 정보가 없으면 running으로 추정하지 않는다. `stale`은 위 상태를 덮어쓰지 않는 최신성 속성이다. 현재 완료 기록을 받았을 때만 완료로 표시하며 브라우저 타이머로 단계를 순차 점등하지 않는다.

## D. 실시간 데이터 연동 설계

### D-1. 채택 아키텍처

**기존 FastAPI에 Live 관측 읽기 API 하나와 공통 목록 어댑터를 추가한다. 생산자·수락 consumer·규칙 detector는 브라우저와 독립 실행한다. P0의 규칙 관측 상태는 Run별 append-only journal과 원자 교체 snapshot으로 보존한다. 정식 분석·Workflow는 기존 저장소를 사용한다.**

```text
실제 Sysmon → #302 producer → immutable EventChunk spool
                                  ↓
                         #302 consumer → PostgreSQL ledger commit → ACK
                                  ↓
                  ACK + ledger + EventChunk hash 검증
                                  ↓
                         독립 Live detector
                                  ↓
                     Run별 관측 journal → snapshot
                                  ↓
                  기존 FastAPI /operations/observations
                                  ↓
                 기존 운영 목록·관측 상세·알림 (1초 polling)

사후 원본 artifact → 기존 canonical 검증/정식 분석 → 기존 저장 결과
                                  ↓
                 독립 Workflow synchronizer → 기존 알림/행위 원장
                                  ↓
                   기존 사건 상세 → 담당자 처리 → 기존 Word 경로
```

P0에서는 수락 consumer·detector·FastAPI가 **동일한 로컬 spool 및 상태 디렉터리를 읽는 배치**로 고정한다. VM producer의 기존 파일 전달 경로를 이 호스트에 연결한다. 실행 호스트·경로 접근이 현재 환경에서 가능한지는 첫 60분 검증 항목이다. 불가능하면 신규 분산 전송 시스템을 개발하지 않고 G의 축소 시연으로 전환한다. 브라우저에서 VM에 직접 요청하지 않는다.

제시된 촬영 계획의 세 추가물 중 adapter/detector와 상태 endpoint는 유지한다. ‘Demo 카드’만 공통 목록·상세 어댑터로 바꾼다. P0에 새 DB 서버·메시지 브로커·Workflow migration은 만들지 않는다.

### D-2. #302 재사용과 수락 경계

재사용 대상은 Sysmon 증분 polling, raw segment, NormalizedEvent, immutable spool, ingress 검증, event/chunk ledger, commit 후 ACK, 중복 처리다. canonical Evidence·Fusion·Human Workflow 구현으로 확대 해석하지 않는다.

Detector 입력은 다음 순서로 승인한다.

1. 허용된 spool root 안의 immutable chunk를 읽는다. API 요청으로 임의 파일 경로를 받지 않는다.
2. ACK의 파일 바이트 SHA-256을 검증한다. ACK 파일의 존재 자체만 신뢰하지 않는다.
3. `chunk_content_sha256`은 원천 canonical message 계산으로 검증한다. **파일 바이트 해시와 canonical chunk 해시는 서로 다른 값이다.**
4. 같은 Run·host·source·channel·chunk ID·sequence·content hash가 commit된 ledger와 일치하는지 확인한다.
5. 이벤트별 식별자·해시를 ledger와 대조하고, detector 자체의 처리 이력으로 중복을 제거한다.

ACK의 `accepted_at`은 현재 구현상 commit 뒤 ACK 생성 시각이다. 정확한 DB commit 시각으로 이름을 바꾸지 않는다. commit 성공 후 ACK 쓰기 전에 중단되면 재전달은 duplicate일 수 있다. **duplicate ACK를 무조건 버리지 않는다.** detector가 미처리한 이벤트라면 처리해야 한다.

Detector가 사용할 본문은 ACK와 결속된 EventChunk다. 식별자·해시 중심의 event ledger만으로 프로세스 계보를 복원하지 않는다.

### D-3. 규칙 판단과 정식 분석의 경계

정책·selector는 촬영 계획에서 동결한 버전과 해시를 사용하고 실제 파일과 일치하는지 확인한다. 판단은 Run·host 안의 ProcessGuid/ParentProcessGuid 계보, 등록된 승인 계보, 동일 PowerShell ProcessGuid의 후속 목적지 연결로 제한한다. PID·이미지명만의 fallback과 Attack/Normal label 참조를 금지한다.

네 가지 detector 상태를 유지한다.

| 원천 상태 | 운영 표시 | 정식 결과/Workflow |
|---|---|---|
| `OBSERVING` | 관측 중 · 판단 자료 수집 | 생성하지 않음 |
| `RULE_NOT_MATCHED` | 현재 관측 범위에서 조건 미충족 | 정상 판정·종결 없음 |
| `DEMO_RULE_MATCH` | 규칙 기반 의심 관측 · 정식 분석 미수행 | 관측 알림만 생성 |
| `ERROR` | 관측 처리 오류 | 성공·안전 상태로 치환하지 않음 |

P0의 규칙 관측은 기존 목록과 상세에서 볼 수 있지만 기존 Human Workflow 쓰기 대상이 아니다. ‘담당자 확인’, 인지 기록, AI 신고서는 정식 분석 알림이 존재하는 항목에서만 활성화한다. 규칙 관측만 선택했을 때는 ‘사후 검증 결과 연결 후 담당자 처리 가능’을 표시한다. 정식 알림을 얻으려고 가짜 Fusion을 만들지 않는다.

11월 5일까지 규칙 관측 자체의 담당자 확인을 지원하려면 P1에서 source가 명시된 별도 관측 업무 원장을 추가한다. 이 확인은 정식 사건 확인·인지시각으로 자동 승계하지 않는다. 기존 `human_workflow_alerts`의 타입 제한을 임시로 우회하지 않는다.

### D-4. 신규 상태 API의 최소 계약

이 절은 **신규 v1 계약**이다. 아래 경로·필드는 현재 구현된 API라는 뜻이 아니다.

`GET /operations/observations?run_id=<id>&after_revision=<n>`

P0는 실행 manifest가 지정한 한 개 활성 Run과 보존된 이전 Run의 명시 조회만 지원한다. Run 생략 시 활성 Run을 응답한다. after_revision은 같은 Run의 revision에만 적용한다. 변경이 없어도 heartbeat/최신성을 확인할 수 있는 200 envelope를 응답한다. 감시 루프의 매 1초 응답 완료 후 다음 요청을 예약하고 중첩 요청은 금지한다.

v1은 항상 해당 Run의 전체 snapshot을 반환한다. after_revision은 변경 여부 판단용이며 delta 삭제/추가 병합 계약이 아니다. 저장된 revision보다 앞선 값을 요청하면 409 RESYNC_REQUIRED로 응답하고 cursor 없이 다시 읽는다. Run이 바뀌면 revision과 선택 generation을 초기화한다. snapshot 크기에 서버 제한을 두고 한도를 초과하면 명시적 오류로 중단한다. 잘라낸 결과를 전체라고 표시하지 않는다.

```json
{
  "schema_version": "operations_observation_v1",
  "server_time": "2026-10-21T06:00:10.000Z",
  "active_run_id": "EXAMPLE-RUN",
  "run_id": "EXAMPLE-RUN",
  "revision": 12,
  "snapshot_at": "2026-10-21T06:00:09.000Z",
  "detector_heartbeat_at": "2026-10-21T06:00:09.000Z",
  "data_origin": "controlled_vm",
  "items": [{
    "observation_id": "OBS-EXAMPLE",
    "run_id": "EXAMPLE-RUN",
    "host_id": "TARGET-A",
    "execution_id": null,
    "source_kind": "live_rule",
    "state": "DEMO_RULE_MATCH",
    "rule_id": "r1-wmi-management-approved-lineage/v0.1",
    "policy_sha256": "<64 hex characters>",
    "selector_version": "r1-structural-lineage-selector/v0.1",
    "selector_sha256": "<64 hex characters>",
    "reason_codes": ["LINEAGE_DEVIATION", "SAME_PROCESS_NETWORK"],
    "last_event_at": "2026-10-21T06:00:07.000Z",
    "rule_evaluated_at": "2026-10-21T06:00:08.000Z",
    "journaled_at": "2026-10-21T06:00:08.100Z",
    "facts": {
      "lineage": [],
      "network": null,
      "context_status": "available"
    },
    "source_refs": [{
      "chunk_id": "CHUNK-EXAMPLE",
      "event_id": "EVENT-EXAMPLE",
      "event_sha256": "<64 hex characters>",
      "chunk_content_sha256": "<64 hex characters>",
      "ack_file_sha256": "<64 hex characters>"
    }],
    "acceptance": "ledger_and_ack_verified",
    "source_completeness": "unknown",
    "canonical_verification": "pending",
    "formal_analysis_ref": null,
    "capabilities": {"human_workflow": false, "ai_report": false},
    "error": null
  }]
}
```

예시는 구조 설명용이며 실제 사건이 아니다. 해시 placeholder와 빈 facts를 match 데이터로 수용해서는 안 된다. 다음 검증 조건을 Pydantic 및 UI 계약 테스트로 고정한다.

| 항목 | 계약 |
|---|---|
| identity | Run·host·관측 ID 필수. observation ID는 Run/host/rule/policy/계보 루트 ProcessGuid/후속 연결 식별자에 결속된 안정적 값 |
| facts | MATCH이면 실제 process GUID·parent GUID·이미지·event ref를 가진 계보, 동일 프로세스의 목적지 IP/port·event ref 필수 |
| 범위 | 모든 item의 Run이 envelope Run과 일치. formal ref가 있다면 Run/host 및 원본 이벤트 매핑 검증 필요 |
| 시간 | timezone 포함 UTC, null 허용 필드는 null 그대로. event time·수신/ACK·규칙 평가·기록·API 생성 시각 분리 |
| 최신성 | API server_time이 새로워도 detector heartbeat와 snapshot이 오래되면 stale |
| unknown | source completeness는 증명 없으면 항상 unknown; Run 종료 버튼으로 verified 변경 금지 |
| 규칙 버전 | policy·selector hash가 바뀌면 기존 관측 결과를 덮어쓰지 않고 새 identity/version 생성 |
| capability | 현재 Live v1은 Workflow/AI false. 정식 ref를 조회해 적격성이 검증된 뒤 별도 정식 상세를 열어야 함 |
| 검증 오류 | 잘못된 schema/범위/해시의 snapshot은 500 DATA_INVALID; 저장소 접근 실패 503; 미등록 Run 404 |
| 버전 | v1 minor 추가 필드는 의미 변경 없이 추가; 필수 enum/의미 변경은 v2. 알 수 없는 상태는 성공으로 표시하지 않음 |

`facts.context_status=missing`은 계보 자료 부족이다. 규칙 조건 미충족과 함께 ‘자료 부족’으로 표시하고 정상 결론을 내리지 않는다. 목록 API에는 command line 전문·자격정보·로컬 파일 경로를 넣지 않는다. 상세 원본은 기존 접근 경계를 재사용한다.

### D-5. 상태 영속성·복구·중복·지연

상태 저장 위치는 `build/live-observations/<run_id>/`를 기본값으로 하고 배포 설정에서 고정한다. Run ID를 파일 경로로 직접 이어 붙이지 않고 허용 패턴·resolved root 검사를 수행한다. 운영 화면의 명칭과 무관하게 원천 `DEMO_RULE_MATCH` 및 출처를 journal에 그대로 보존한다.

- 단일 writer가 검증한 관측과 처리한 이벤트 identity를 journal record 하나로 append하고 flush/fsync한다. 그 뒤 같은 디렉터리의 임시 파일을 원자 교체해 snapshot을 만든다.
- journal을 원본으로 취급하고 snapshot은 재생성 가능하게 한다. detector 재시작 때 journal로 처리 이력·계보 상태를 복원한 뒤 ACK된 spool을 재스캔한다.
- commit/ACK 후 detector 중단, journal 후 snapshot 전 중단, snapshot 후 UI 응답 전 중단을 각각 재현한다. 재처리 효과는 멱등하게 만들며 ‘exactly once 전송’이라고 주장하지 않는다.
- 끝의 불완전 JSONL record는 복구 경고와 함께 격리하고 마지막 완전 record부터 재개한다. 중간 record 손상은 처리 중단·오류로 드러낸다.
- 같은 event ID·다른 hash는 오류 및 격리다. chunk 재전달로 신규 알림·이벤트 수가 늘지 않아야 한다.
- 순서가 뒤바뀐 EID 3/EID 1은 Run별 계보 저장소에서 재평가한다. UI 도착 순서를 event time으로 간주하지 않는다. 수집 중단이나 candidate boundary를 source watermark로 만들어서는 안 된다.
- Run을 바꾸면 상태·계보·notification key를 분리한다. 이전 Run의 pre-run context를 임의 재사용하지 않는다. 승인된 같은 Run context 결속만 허용한다.
- Run의 수집을 운영자가 종료해도 `source_completeness=unknown`은 유지한다. canonical 검증 결과는 해당 경로에서 실제 확인한 범위만 표시한다.

Polling은 Live 1초, 기존 runtime/Workflow 5초를 유지한다. 모든 endpoint를 1초로 바꾸지 않는다. 기존 목록은 완료 전환뿐 아니라 5초 주기 재조회로 짧은 실행 누락을 보완한다. 최근 5개 runtime 목록만으로 전체 사건 동기화를 대신하지 않는다.

Live heartbeat는 detector가 1초마다 별도로 보고한다. 5초 초과는 ‘보고 지연’, 15초 초과는 ‘상태 미확인’으로 정한다. 이는 P0 UI 기준이며 탐지 SLA가 아니다. 현재 runtime의 기존 5분 stale 기준과 혼용하지 않는다. 네트워크 실패 시 2→4→8초, 최대 10초 backoff를 적용한다. 이전 값은 마지막 확인 시각과 함께 정지시켜 표시하며 running 애니메이션은 멈춘다. 복구 시 전체 snapshot을 다시 읽는다.

브라우저가 숨겨지면 polling을 늦추거나 멈춰도 서버 처리는 계속된다. 재접속 시 누적 항목을 한꺼번에 요약하고 과거 모든 알림을 연속 팝업하지 않는다. toast 중복 키는 source kind + observation/alert ID + revision으로 하며, 같은 사건의 단순 heartbeat는 새 알림을 만들지 않는다. localStorage의 표시 여부는 업무 확인 기록으로 사용하지 않는다.

### D-6. canonical·정식 분석 연결

Run 종료 후 canonical 결과를 읽을 때 같은 Run·host·source event ID·원본 참조·해시를 검증한다. 다른 표기 체계면 검증 가능한 원본 대응표가 있어야 한다. 일치하면 Live 관측에 읽기 전용 `formal_analysis_ref`를 붙여 ‘연결된 정식 분석 열기’를 제공한다. 자동으로 과거 관측을 정식 탐지로 덮어쓰지 않는다.

같은 Run이라는 사실만으로 충분하지 않다. 연결 자료가 부족하면 `unverified`, 충돌하면 `mismatch`다. 검증 완료도 source completeness나 causal 적격을 자동 보장하지 않는다. canonical Evidence가 있어도 Fusion/Decision이 없으면 ‘근거 검증 완료 · 정식 판단 없음’으로 남는다.

### D-7. 측정 가능한 지표의 범위

| 지표 | 지금 가능한 범위 | 추가 개발/금지 사항 |
|---|---|---|
| 누적 Run 수 | `/overview.total_runs` | 분석 성공 건수와 다름 |
| 최근 실행·실패 | runtime 반환 범위의 상태와 완료시각 | 전역 1시간 성공/실패율에는 기간·중복 실행 기준을 가진 DB 집계 필요 |
| 정규화·증거 처리량 | telemetry 1초 bucket의 실제 완료 record 수, 실행 시도 기준 | 입력 총량이나 API 응답 건수를 실시간 수집량으로 바꾸지 않음 |
| 처리 시간 | `processing_latency_sum_ns / sample_count / 1e6` ms | 샘플 없으면 null; 평균의 단순 평균 금지; 탐지 지연·TTSD 아님 |
| Live 수락 이벤트 수 | 신규 adapter의 unique event journal count | 신규 계측. 기존 telemetry로 이미 제공된다고 주장하지 않음 |
| 미확인 정식 알림 | 저장 알림 중 `analyst_ack_time=null` | 전체 집계 read API 추가 필요. 화면에 선택된 Run만으로 전체 건수 계산 금지 |
| 규칙 의심 관측 수 | MATCH identity의 중복 제거 수 | 정식 사고 건수에 합산하지 않음 |
| 서비스 가동 시간 | 현재 UI는 미계측; 프로세스 start/heartbeat가 있어야 가능 | 마지막 Run 시작시각을 시스템 uptime으로 사용 금지 |
| 큐 적체·종단 지연 | 현재 확인 범위에서 미계측 | 실제 queue 관측, 서버/소스 시각 정합성 추가 필요; P2 |
| 실패/지연 증가 | 비교 기간·동일 모집단·충분한 샘플이 있을 때만 | P0에서는 ‘최근 조회 범위 실패 N건’처럼 사실만 표시 |

P0는 기존 실측 차트만 재사용하고 Live는 건수·최종 관측시각·계보로 충분하다. P1에서 최근 5분 처리량과 평균 처리 시간 두 개만 다듬는다. LLM으로 운영 요약을 만들지 않는다.

## E. Human Workflow 최종 설계

### E-1. 알림 생성과 사람의 행위를 분리

정식 결과가 commit되면 독립 서버 작업이 기존 `HumanWorkflowRepository.synchronize()`를 호출한다. P0는 1초 주기의 단일 로컬 조정 프로세스로 기존 저장 Run을 빠짐없이 조회하고 고유 source key로 중복을 막는다. 최종 5건 제한을 사용하지 않는다. 오류 후 반복 스캔으로 회복하며 GET 조회로 새 알림을 만들지 않는다. P1에서 watermark/reconciliation·증분 조회로 확장한다.

현재 작업은 작은 로컬 데이터셋을 전제로 한다. 전체 스캔 비용이 한 주기를 넘으면 지연 상태를 보고하고, 같은 작업을 겹쳐 실행하지 않는다. startup, heartbeat, 마지막 성공 범위·오류를 남긴다. 사용자가 화면을 열기 전에 저장된 알림이 존재하는지 시험한다.

현재 `synchronize()`는 해당 범위의 최신 Decision head를 읽는다. 따라서 P0의 주기적 재조회는 최신 상태 복원이며, 두 조회 사이에 생겼다가 교체된 모든 중간 판단 버전의 알림을 보장하지 않는다. 촬영은 동결된 결과를 가진 Run으로 검증하고 이 한계를 증적에 남긴다. P1은 영속 Decision 이력을 cursor로 순회하고 각 버전의 immutable snapshot에서 알림 후보를 생성하도록 확장한다. 사건 목록의 현재 상태와 개별 판단 버전의 감사 이력을 분리한다.

기존 `issued_at`은 알림 원장 삽입시각으로 유지한다. `detected_at`은 원천 분석 결과 시각, 브라우저 표시 시각은 선택적 UI 기록이다. 과거 Run 재분석·재동기화에서 이 시각들이 다를 수 있다.

### E-2. 행위별 UX·저장 규칙

| 단계 | 사용자 동작 | 저장 및 완료 조건 |
|---|---|---|
| 알림 표시 | 비차단 toast의 ‘사건 보기’ | 화면 열기/닫기 자체는 업무 기록 없음 |
| 담당자 확인 | ‘담당자 확인 기록’ | 서버 시각 `analyst_ack_time`, actor, action, version 저장 성공 후 완료 |
| 근거 검토 | 관측·검증 범위를 읽고 ‘근거 검토 완료’ | `evidence_reviewed_at`와 actor 저장. raw verified 상태를 변경하지 않음 |
| 내부 인지 기록 | ‘지금 인지로 기록’ 또는 ‘이전 시각 입력’ | `t_h`와 `t_h_recorded_at` 분리. 과거 입력·정정 사유 필수 |
| 내부 대응 목표 | 기록된 인지시각 표시 | `due_at=t_h+24h`, server_time 기준 남은 시간 표시 |
| 신고 진행 결정 | 진행 / 보류 / 진행하지 않음 + 사유 | `report_choice/report_decided_at` 저장. 인지 기록과 독립 |
| 초안 생성 | 사고 유형·관측 범위 확인, AI 요청 내용 확인 | 기존 승인 snapshot/버전/멱등 계약 통과 후 생성 |
| 초안 검토 | 내용 확인 후 ‘초안 검토 완료’ | draft ID·버전·검토시각. 생성 성공과 구분 |
| Word | 양식 입력 확인, 생성/다운로드 | 정확한 draft/form 버전과 DOCX hash 연결. 다운로드는 외부 제출이 아님 |

기본 안내 순서는 확인→검토→인지→신고 결정→초안이다. 그러나 신고 결정과 인지는 서로 다른 기록이다. 현재 backend도 확인·검토 후 신고 결정을 먼저 허용하므로 이 사실을 UI에서 숨기거나 과거 데이터를 다시 쓰지 않는다. P0는 안내 순서를 적용하고 existing API 의미를 유지한다. 긴급 업무 때문에 실제로 앞선 인지를 나중에 기록하는 경우 `t_h`가 확인/검토보다 빠를 수 있다.

근거 검토 완료는 ‘담당자가 현재 자료와 한계를 검토했다’는 뜻이다. 원본 미검증 상태라면 이를 완료 대화상자와 감사 사유에 명시한다. 보고서 입력의 원본 검증 게이트는 별도로 계속 적용한다.

카운트다운 명칭은 **‘내부 대응 목표 · 인지 기록 기준 24시간’**으로 고정한다. `t_h`가 없으면 시작하지 않는다. 기한이 지났으면 0에서 멈추지 않고 ‘목표 시각 N시간 경과’로 표시한다. 법적 신고기한·신고의무·법적 인지를 자동 확정하는 UI 문구를 쓰지 않는다. 이 문서는 법령 적용을 판단하지 않는다.

### E-3. 시간·감사·재접속

저장은 UTC timezone 포함 값을 유지한다. 기본 화면은 KST 초 단위, 감사 상세는 밀리초 이상과 원본 UTC를 함께 제공한다. 같은 초에 여러 행위가 있으면 ‘동일 초 내 기록 · 상세 보기’를 표시한다. 인위적으로 1초씩 벌리거나 과거 원장을 보정하지 않는다. 감사 순서는 action version/recorded_at이며 사용자가 입력한 과거 `t_h` 순으로 정렬하지 않는다.

`expected_version`과 `idempotency_key`를 재사용한다. 응답이 유실된 재시도는 같은 key·같은 body를 보낸다. 409면 최신 상태를 읽고 입력을 보존한 채 재확인을 요구한다. 버튼 클릭 즉시 완료를 표시하지 않는다. 서버 재시작 후 PostgreSQL Workflow와 기존 SQLite의 초안·양식 버전에서 복원한다.

### E-4. AI와 Word 재사용 범위

Claude Haiku 4.5를 유지한다. 현재 코드의 요청 모델은 `claude-haiku-4.5`, 기대 응답 모델은 `claude-haiku-4-5-20251001`이다. 요청 당시 모델·prompt·정책·실제 요청 본문·입력 snapshot hash를 기록하는 기존 계약을 재사용한다.

실제 데이터에 대한 기존 외부 전송 경계는 유지한다. 현재 구현된 **비식별 요청 snapshot 미리보기→개별 승인→생성** 흐름을 사용한다. 이것은 코드에 이미 존재하는 제품 절차다. 설계 검토 자체를 위해 신규 외부 전송이나 승인을 실행하지 않는다.

HTTP 200만으로 ‘AI 작성 성공’이라 표시하지 않는다. 모델·응답 형식·근거 문장 검증까지 통과해야 한다. 실패 후 Jinja2 경로는 ‘대체 작성’으로 표시한다. Word 실패 시 검증된 AI 초안은 보존하고 양식 단계만 재시도한다.

**R1 WMI 관측을 기존 AI 생성기에 바로 연결할 수 있다는 전제는 기각한다.** 현재 승인 서술은 제한된 관측 유형(인코딩 PowerShell, 스크립트 인터프리터의 주소 연결 등)을 허용한다. WMI 계보 이탈 의미와 R1 canonical provenance가 동일 계약을 충족하는지는 확인되지 않았다. P0에 이 범용화를 추가하지 않는다. R1 적격 입력이 없으면 해당 사건의 AI 버튼은 비활성화하고 검증된 별도 사례로 기능을 시연한다.

사고 발생시각·원인·피해 규모·유출·대응조치는 사람이 확인한 값 또는 명시적 미확인으로 남긴다. event time을 사고 발생시각으로 전환하지 않는다. DOCX는 기존 KISA 템플릿과 렌더러를 유지한다. PDF/HWP 신규 출력과 자동 외부 제출은 이번 범위에서 제외한다.

### E-5. 인증과 알림 채널

10월 23일에는 실제 로그인처럼 보이는 가짜 로그인 화면을 만들지 않는다. 기존 loopback·동일 Origin 경계를 유지하고 ‘로컬 담당자’로 촬영한다. 임의로 서버를 `0.0.0.0`에 열어 현재 로컬 전용 action API를 공유하지 않는다.

11월 5일 P1에서 실제 계정 식별·세션·조회자/대응자 권한·감사 actor 주입을 함께 구현한다. action API뿐 아니라 Run·증거·신고서 조회/다운로드도 같은 접근 정책을 적용한다. `DEMO_ACTOR` 상수, DB actor CHECK, report approval actor를 같이 바꿔야 한다. 인증 미완성 상태면 통제 로컬 시연 범위를 유지하고 운영 배포 완료를 주장하지 않는다.

이메일·문자·메신저는 P2다. 서버측 알림 저장·재접속 복원이 먼저다. 외부 채널은 향후 outbox·전달 결과·재시도·대상 설정까지 갖출 때 연결한다.

## F. 개발 우선순위 및 작업 범위

P0는 10월 23일 제출에 필수, P1은 11월 5일까지 중요, P2는 후속이다. 아래 시간은 **인일이 아닌 작업시간 추정**이며 실제 가용 인원이 확인되지 않았다. 수집 담당 1명과 Dashboard 담당 1명이 병행하고, 검증·촬영을 함께 수행한다는 조건이다. 한 명만 가능하면 신규 Live 통합 범위를 줄이고 G의 축소 경로를 적용한다.

### Phase 1 — 10월 23일 영상 제출까지

| 작업 | 목적 | 재사용 기능 | 신규 구현 | 담당 영역 | 완료 조건 | 우선순위 |
|---|---|---|---|---|---|---|
| 실행 기준·계약 동결 (0.5~1h) | 로컬/원격/실행 서버 혼용 방지 | 현재 코드·실증 artifact | manifest, 정확한 spool/DB/store 식별 | 통합 담당 | #302 실행 코드와 로컬 변경이 함께 재현됨 | P0 |
| 수락 adapter/detector (2~3h) | 실제 이벤트를 관측 결과로 변환 | #302·selector·policy | ACK/ledger 결속, journal/snapshot | 수집 담당 | 미수락 입력 차단, label 미사용, duplicate 재개 | P0 |
| Live API·목록/상세 (2~3h) | 같은 운영 화면에서 표시 | FastAPI·테이블·상세 컴포넌트 | v1 DTO, source 분기, 1초 polling | Dashboard 담당 | Run 격리·schema 오류·재접속 포함 표시 | P0 |
| 독립 정식 알림 동기화 (1~2h) | 브라우저 없이 알림 저장 | repository.synchronize·unique source key | 서버 조정 프로세스, GET 전환 | Backend 담당 | 브라우저 종료 중 결과 생성 후 알림 존재 | P0 |
| 필수 의미 수정 (1~2h) | 오해 방지 | 기존 상태 presenter·audit UI | 분기 경로, 출처 배지, 인지 두 시각, toast | Dashboard 담당 | 미실행 Fast/미검증 Evidence를 완료로 표시하지 않음 | P0 |
| 기존 Workflow·AI·DOCX 회귀 (1~2h) | 완성 기능 재사용 | 기존 테스트·검증 사례 | 재촬영 및 코드/데이터 버전 고정 | 검증 담당 | 동일 사례에서 저장·새로고침·파일 복원 | P0 |
| 실제 VM smoke·촬영 (공동 2~3h + 편집 3~4h) | 제출 증거 확보 | runner·OBS·canonical 도구 | 시각/Run 자막·manifest·해시 | 수집/촬영 담당 | 재생 가능한 4~6분 MP4와 증적 ZIP | P0 |

새 차트·디자인 전면개편·R1용 LLM 서술 확장은 이 표에 없다. 통합이 길어지면 먼저 이들을 미루는 것이 아니라 **처음부터 착수하지 않는다.**

시간 기준은 모두 KST다. 10월 21일에 계약·실행 기준을 고정하고 10월 22일 12:00까지 실제 수락 이벤트가 같은 운영 화면에 표시되어야 한다. 10월 22일 16:00에는 촬영 가능 버전을 동결한다. 10월 23일은 편집·검수·제출 여유로 남긴다. 착수가 늦거나 수집팀의 기존 Go/No-Go가 더 빠르면 더 빠른 동결 시각을 따른다. 이미 지난 시간표를 달성한 것처럼 기록하지 않는다.

### Phase 2 — 11월 5일 외부평가까지

| 작업 | 목적 | 재사용 기능 | 신규 구현 | 담당 영역 | 완료 조건 | 우선순위 |
|---|---|---|---|---|---|---|
| R1 canonical 및 정식 분석 연결 | 실수집 증거와 기술 성과 연결 | 기존 batch/canonical·증분 검증 모듈 | 원본 대응표·명시 결과 연결·불일치 처리 | 수집/모델링/Backend | 동일 Run 원천 결속으로 결과 재현, 미평가 경로 그대로 표시 | P1 최우선 |
| source completeness·causal 적격 검증 | 성능 주장 가능 범위 확립 | required partition·close proof 계약 | 실제 source proof 경로의 부족분 | 수집/평가 | 승인된 proof 없으면 causal/TTSD 미주장. 달성 자체는 보장하지 않음 | P1 연구 게이트 |
| 계정·권한·실제 actor | 운영 사용자 책임 기록 | 기존 Origin·멱등·감사 원장 | 인증, 역할, migration, actor 전달 | Backend | 권한 없는 읽기/쓰기 거부, 실제 actor로 감사 저장 | P1 |
| 관측 업무 원장·전역 집계 | Live 항목도 확인·추적 가능 | v1 observation ID·기존 액션 패턴 | 별도 관측 action 원장, 기간 집계 API | Backend | 재시작 후 확인 복원; 정식 업무와 자동 합산/승계 없음 | P1 |
| 알림 조정·장애 복구 보강 | 누락 없는 장기 운영 | P0 조정 프로세스 | 증분 cursor, 재조정, 건강상태, bounded query | Backend | 중단·재시작·새 Decision 버전에서도 누락 없음 | P1 |
| 실측 차트·운영 요약 | 처리 변화 파악 | telemetry·chart·runtime API | 정의된 집계와 freshness 문구 | Dashboard | 모집단·측정구간·null 처리 검증 | P1 |
| R1 신고서 관측 유형 확장 | 동일 R1 사건 보고서 연결 | approved snapshot·grounded validation·DOCX | R1 allowlist·재검증·참조 계약 | 신고서/증거 담당 | 검증되지 않은 계보·피해 문장 거부, 적격 R1 E2E | P1, 증거 연결 후 |
| 반응형·접근성·대용량 목록 | 실제 사용성 | 현재 CSS·목록 | 페이지 처리·포커스·좁은 화면 보완 | Dashboard | 1366/1920/1024, 키보드 업무 완료 | P1 |
| 외부 채널·모바일 전체·SSE | 후속 확장 | 기존 알림 identity | 전달 outbox·구독·채널 관리 | 후속 | 별도 요구/운영 검증 | P2 |

10월 24~28일에는 데이터 연결·복구·actor 기반을, 10월 29~11월 2일에는 모델/증거 검증과 UX 회귀를 우선한다. 11월 3일 이후에는 기능을 동결하고 리허설·결함 수정만 한다. 전체 팀의 실제 가용 시간이 부족하면 외부 알림, 새 차트, R1 문장화 순으로 줄인다. 모델·증거 검증 시간을 UI 작업에 전용하지 않는다.

## G. 시연 시나리오 최종 권고

**주 영상은 팀 전체 프로젝트의 업무 흐름을 보여주는 5분 30초로 정한다. R1 수집은 앞부분의 실제 데이터 유입 증거로 사용하고, 기존 검증 사례의 담당자·AI·Word 기능은 별도 사례임을 명시해서 보여준다.** R1 기술 검증만으로 영상을 채우면 프로젝트가 수집기와 규칙 비교기로 보이고 이미 구현된 대응 지원 가치가 빠진다. 세부 R1 검증은 실행 증적과 필요시 별도 기술 클립으로 보완한다.

| 시간 | 장면 | 설명·경계 |
|---|---|---|
| 0:00~0:20 | 목적·운영 Dashboard | 통제 실험 환경, 관측→검토→대응 기록→신고서 지원 |
| 0:20~1:00 | 실제 WMI 실행·새 관측 유입 | 실제 Sysmon·수락·갱신. 관측 ID와 Run 표시 |
| 1:00~1:25 | 승인 계보 사례 | 현재 관측 범위 조건 미충족. 정상 판정이라고 말하지 않음 |
| 1:25~2:05 | 이탈 계보+동일 프로세스 연결 | 규칙 의심 관측, 정식 Fusion 미수행 표시 |
| 2:05~2:35 | 사후 canonical 확인 | 같은 원본 결속과 검증 범위. 대기 축약 시 실제 경과시간 자막 |
| 2:35~2:45 | 명시적 사례 전환 | ‘이후는 별도 검증 사례 ○○의 대응 업무’ 전체 화면 자막 및 ID 변경 |
| 2:45~3:40 | 정식 결과·확인·검토·인지·신고 결정 | 각 행동은 실제 클릭·저장. t_h와 기록시각 분리 |
| 3:40~4:50 | AI 요청 확인→생성→근거 검증→Word | 실제 성공 모델·작성 방식 표시. 기존 합성 사례라면 합성 출처 유지 |
| 4:50~5:15 | 새로고침·Word 열기 | 저장 상태 복원, DOCX 본문과 미확인 항목 확인 |
| 5:15~5:30 | 입증 범위 | 실수집/규칙 관측, 별도 검증 사례의 AI·문서 지원, 미입증 범위 |

기존에 처리 완료된 Run을 초기화해서 새 작업처럼 촬영하지 않는다. 미리 수행한 흐름은 기록 재생이라고 밝히거나 새 검증 fixture Run으로 수행한다. 기존 두 시나리오 길이를 영상에 맞춰 임의 변경하지 않는다. 컷 편집에는 원본 UTC·Run·실제 경과시간을 남기고 영상 길이를 탐지 시간으로 사용하지 않는다.

**Go 조건:** 실제 VM 이벤트→commit/ACK→검증된 detector 입력→같은 운영 목록 갱신, 재시작 복원, Run 혼입 0, label 의존 0, Normal 사례 false match 0이 해당 리허설에서 확인된다. 이는 리허설 합격 기준이며 일반 성능 수치가 아니다.

**No-Go 시 하나의 축소 경로:** 새 Live 통합 개발을 중단하고 실제 수집·ledger ACK·사후 canonical을 증적으로 보여준 뒤, 기존 Dashboard에서 검증된 정식 사례의 담당자→Word 흐름을 촬영한다. ‘실시간 Dashboard 연동 미완료’를 명시한다. 임시 시연 사이트나 가짜 상태를 만들지 않는다. canonical도 실패하면 성공 컷을 대체 생성하지 않고 확보된 수집 범위와 기존 별도 사례만 제출한다.

증적 ZIP은 실행 commit + 로컬 변경 manifest, 실행 설정의 비밀정보 제외본, VM/Run/host 식별, policy/selector hash, 원본·chunk·ACK·ledger 결속 검사, 관측 journal/snapshot, canonical 비교, Workflow 감사 기록, 요청/출력 검증 메타데이터, DOCX hash, 컷별 타임라인과 실패·재촬영 내역을 포함한다. 합성/통제 실수집을 각각 표시하고 촬영 Run은 성능 평가 집합에서 제외한다.

## H. 위험 요소 및 대응

| 위험 | 현재 근거/발생 조건 | 대응 및 중단 기준 |
|---|---|---|
| #302와 로컬 UI 미통합 | 현재 작업 트리에 producer/wiring 없음 | 실행 기준부터 통합. 첫 시간에 경로 확인 안 되면 Live 범위를 줄임 |
| 대량 미커밋 변경 손실 | UI·Workflow·신고서·migration 분산 | 새 통합 작업 공간에 보존 snapshot 반영. 현재 디렉터리에서 강제 reset/rebase 금지 |
| ACK 이후 유실/중복 | detector와 수락 ledger는 다른 저장 경계 | durable journal, 재스캔, event hash dedup; duplicate ACK 미처리 이벤트 회수 |
| source completeness 과장 | #302 final close 자동 발급 금지 | 종료와 완전성 분리. TTSD/실시간 조기인지 성능 비주장 |
| 임시 규칙을 정식 결과로 오인 | 동일 화면으로 통합 | 출처·분석 방식·검증 상태 기본 표시; 정식 테이블 저장 금지 |
| 알림이 접속 시에만 생성 | 현재 UI sync POST | 독립 조정 프로세스, 브라우저 닫기 시험 |
| 시각 혼동 | 같은 초의 자동화 행위, 과거 로그시각과 현재 기록시각 | 감사 밀리초, t_h/t_h_recorded_at 분리, 원장 수정 금지 |
| R1 AI 작성 실패 | 허용 관측 유형·provenance 미확인 | 별도 검증 사례 시연. P1에서 허용 계약 확장 |
| 서로 다른 서버/Run 혼용 | 8815/8816의 데이터 집합 상이 | 한 촬영 버전·환경 manifest, 사례 전환 자막 |
| SQLite 파일 누락 | 보고서/양식은 PostgreSQL 외 store 사용 | DB·SQLite·원본 mirror를 함께 백업/복원 검증, P0 저장소 재작성 금지 |
| 화면 지표 과장 | runtime 제한 목록·희소 telemetry | 범위 표시, unknown/null 유지, 측정 정의별 차트 |
| 인증 외관만 구현 | local actor 및 DB 고정 CHECK | P0 로컬 명시; P1 서버 권한·actor·migration 동시 구현 |
| 일정 초과 | Live·사후 분석·AI 완전 연결을 한 번에 시도 | 10/22 정오 Go/No-Go, 16시 동결, 기존 기능 우선 촬영 |
| 연구 기여가 UI에 가림 | 규칙 detector가 전면에 보임 | 평가 탭·증적에서 Fusion/Stopping/Hybrid의 실제 수행·미평가 분리, 모델 검증 우선 |

11월 5일까지 실제 병렬 Fast/Fusion 실행과 평가를 입증하지 못했다면 병렬 설계 지원과 현재 실행 수준을 구별한다. 매력적인 분기 그림이 실행 증명을 대신하지 않는다.

## I. 구현 착수 지침

### I-1. 유지·수정·추가·제외

| 구분 | 결정 |
|---|---|
| 유지 | 기존 FastAPI/JavaScript, 운영 화면·상세 탭, telemetry/증거 조회, Workflow 원장·멱등, Claude Haiku 4.5, 승인 snapshot, KISA DOCX |
| 수정 | 브라우저 sync 의존, 직렬 pipeline 표현, source/검증 배지, t_h 기록시각 표시, polling 범위·알림 UX, 개발 명칭 |
| 추가 | ACK 검증 adapter, 관측 journal/snapshot, Live v1 읽기 API, 공통 목록 source 분기, 독립 알림 조정, 실행 manifest |
| 이번 제출 제외 | 새 사이트·전체 프런트엔드 교체·새 그래프·운영 로그인·외부 알림·R1 범용 LLM·공식 TTSD·자동 신고·PDF/HWP |

### I-2. 담당 간 인계 계약

| 소유자 | 책임 | 상대에게 전달할 것 | 책임 밖 |
|---|---|---|---|
| R1 수집 담당 | producer/spool/ledger/ACK·Run 격리·시간·원본 보존 | ACK와 일치하는 chunk 경로, partition 계약, policy/selector hash, 샘플 4상태·실패 fixture | UI 상태색·Workflow·정식 Fusion 위장 생성 |
| Detector 담당 | 수락 확인·GUID 계보·규칙·durable journal | v1 snapshot, identity·revision, reason·facts·refs, 재시작 절차 | source completeness의 임의 선언 |
| Dashboard Backend | 읽기 API·버전/범위 검증·독립 알림 조정 | 검증된 DTO·오류 코드·capability·server time | ground truth로 상태 계산 |
| Dashboard UI | 기존 목록/상세·알림·freshness·동작 게이트 | 화면 계약 테스트·캡처·키보드 검증 | raw 이벤트 자체 판정·기록 시각 생성 |
| 증거/모델 담당 | canonical·정식 결과·causal 적격 검증 | 원본 대응표·실행 모드·검증 범위 | 규칙 일치를 모델 성과로 승격 |
| 신고서 담당 | 지원 관측 allowlist·snapshot·Claude·Word | 입력 적격 조건·초안/양식 버전·실패 상태 | 미확인 피해 추정 |
| 통합 담당 | 기준 코드·DB/migration·artifact·촬영 동결 | 실행 manifest·승인된 시험 결과·제출 ZIP | 검증되지 않은 완료 선언 |

수집 담당이 별도 팀원이라는 현재 상황에 맞춘 책임 분리다. 인원 추가를 전제하지 않으며 한 사람이 여러 역할을 맡을 수 있다.

### I-3. 가장 먼저 확인할 코드·API·DB

1. 로컬 변경을 포함한 코드 snapshot, 실제 원격 SHA, #302 파일 존재 및 동일 selector/policy.
2. FastAPI 실행 경로와 module version, `/healthz`·`/operations/runtime-context`·Workflow·snapshot·KISA API 제공 여부. 404를 단순 데이터 없음으로 처리하지 않는다.
3. 실제 DB의 stream ledger, `014_human_workflow.sql` 적용, 원본 보존 관련 migration, 인덱스·제약. 기존 migration 번호가 원격 추가 migration과 충돌하는지 확인한다.
4. 설정된 report SQLite·KISA store·raw mirror 위치와 파일 접근, source Run/host 일치. `.env`·credential은 문서/화면에 복사하지 않는다.
5. live spool과 ACK 원본 접근, ledger read 권한, VM 시각 동기 상태, pre-run WmiPrvSE context.
6. UI에서 비교할 timestamp의 실제 API 값·audit 원본·표시 함수. 현재 확인한 901 이외의 문제 사례가 있으면 같은 방식으로 대조한다.

현재 작업 트리의 HEAD만 cherry-pick하면 신규 Workflow/신고서 파일이 빠진다. 통합자는 tracked diff와 미추적 소스·템플릿·tests를 함께 보존하고, build 전체나 credential을 무조건 commit하지 않는다. 별도 통합 checkout에서 최신 develop과 충돌을 해결한다. UI·API·migration·pipeline 변경을 논리 단위로 검토하고 동결 manifest에 commit + 필요한 patch hash를 적는다. 이 설계 검토에서는 checkout·merge·commit·배포를 수행하지 않았다.

### I-4. 권장 착수 순서

1. 60분 이내 기준 코드·서버·DB·spool 확인, D의 v1 DTO와 sample fixture 동결.
2. 수집 담당은 accepted adapter/detector를 구현하고 Dashboard 담당은 같은 fixture로 목록/상세를 연결.
3. 실제 ACK된 이벤트로 교체, label 배제·Run 격리·dedup·오류를 검증.
4. 정식 알림 조정을 서버로 이동하고 기존 Workflow를 GET 조회 중심으로 연결.
5. 시간·출처·단계 의미만 우선 수정. 기존 AI/Word 회귀 확인.
6. 실제 VM smoke와 브라우저 종료/복구 검증으로 Go/No-Go 결정.
7. 코드·설정·데이터셋 동결 후 촬영·검수·증적 패키징.

### I-5. 완료 기준

| 검사 | 합격 기준 |
|---|---|
| 실제 입력 | 제출 Run의 Sysmon EID 1/3, 원본·chunk·ledger·ACK·관측 연결 가능 |
| 수락 검증 | 미commit·ACK 변조·hash 불일치 입력으로 match 생성 불가 |
| ground truth 배제 | label만 바꾸어도 detector 결과 동일, 입력 DTO/코드에서 label 미참조 |
| 계보 정확성 | 동일 GUID 연결만 인정, 다른 PowerShell·PID 재사용·자료 부족 반례 처리 |
| 중복·복구 | 동일 chunk 재전달·ACK duplicate·detector 중단 후 observation ID/건수 안정 |
| Run 격리 | A 지연 응답·A 캐시가 B 화면·인지·초안을 변경하지 못함 |
| 상태 표시 | 실패·지연·미실행·미구현·미검증 구분; 가짜 진행 없음 |
| 브라우저 독립 | 브라우저를 닫은 동안 수집/분석/알림 기록 진행, 재접속 때 복원 |
| 시간 기록 | 명시 클릭만 기록, t_h와 recorded_at 분리, 같은 초 표시·과거 인지·미래 입력 거부 |
| 동시성 | 이중 클릭·응답 유실·409에서 중복 행위나 조용한 덮어쓰기 없음 |
| AI·Word | 적격 snapshot만 전송, HTTP 200+출력 검증, 대체 작성 구분, 현재 버전의 DOCX 다운로드 |
| 미지원 R1 | 정식 결과 없는 관측에서 Workflow/AI 활성화 불가; 다른 Run으로 몰래 fallback 없음 |
| 재시작 | Workflow·초안·양식·원본 참조 복원. 다운로드 파일 hash 검증 |
| 화면 | 1366/1920 주요 업무 가능, 새 사건이 폼/선택을 빼앗지 않음 |
| 제출물 | MP4 전체 재생, 컷별 Run·출처, ZIP manifest·해시·실패 기록 존재 |

이번 검토에서 재실행한 명령은 Python의 `tests/dashboard/test_human_workflow.py`, `tests/dashboard/api/test_approved_report_snapshots.py`, `tests/dashboard/api/test_runtime_context.py`와 Node의 `test_dashboard_operator_contract.mjs`, `test_dashboard_workflow_controller.mjs`, `test_dashboard_runtime_context.mjs`다. 각각 41/43개 통과했다. 최초 Python 실행은 사용자 Temp 폴더 권한으로 7개 fixture setup 오류가 났고, 새 workspace 내부 `--basetemp`를 지정한 재실행에서 전부 통과했다. 새 Live 계약과 실제 VM 조건은 아직 시험 전이다.

### I-6. 근거 파일 안내

- 화면: 검토한 화면 `build/operator-ui-redesign/after/overview-1920.png`(로컬 산출물, 저장소 미포함), [dashboard.js](../src/incident_awareness/dashboard/ui/assets/dashboard.js).
- Workflow: [행위 모델](../src/incident_awareness/dashboard/human_workflow.py), [저장 repository](../src/incident_awareness/storage/repositories/human_workflow_repository.py), [local actor API](../src/incident_awareness/dashboard/api/human_workflow.py), [DB 제약](../infra/postgres/migrations/014_human_workflow.sql).
- 표시: [Workflow controller](../src/incident_awareness/dashboard/ui/assets/dashboard-workflow-controller.mjs), [운영자 표시 계약](../src/incident_awareness/dashboard/ui/assets/dashboard-operator-contract.mjs).
- 계측: [telemetry read model](../src/incident_awareness/dashboard/telemetry_read_model.py), [runtime context](../src/incident_awareness/dashboard/api/runtime_context.py).
- 실행: [standalone](../src/incident_awareness/pipeline/standalone.py), [stream ingress](../src/incident_awareness/pipeline/r1_stream_ingress.py), [stream ledger](../src/incident_awareness/storage/repositories/r1_stream_delivery_repository.py).
- 신고서: [승인형 작성 계약](approved-llm-report.md), 기존 실증 기록 `build/approved-llm-report/REPORT.md`(로컬 산출물, 저장소 미포함), [지원 관측/요청 계약](../src/incident_awareness/reporting/approved_snapshot.py), [신고서 API](../src/incident_awareness/dashboard/api/report_drafts.py).
- 사용자 제공 촬영 계획: IDE에 열린 `R1_내부평가_시연_영상_촬영_계획.md`를 읽었으며 파일 자체는 변경하지 않았다. 이 문서는 해당 계획의 Demo 카드 방식을 공통 화면 통합으로 수정한다.

## J. 최종 의사결정

**단일 운영 Dashboard의 기존 구조를 유지하고, Live 규칙 관측을 공통 목록·상세의 별도 원천으로 추가하는 B 수정안을 확정한다. 개발 순서는 ‘기준 코드와 수락 계약 고정 → 실제 이벤트의 관측 연결 → 독립 알림 저장 → 기존 담당자·AI·Word 기능 재사용 → 실측·인증·R1 정식 연결 보강’이다.**

| 질문 | 확정 답변 |
|---|---|
| Q1. B안이 최선인가 | 그렇다. 동일 제품 UI를 쓰되 표시 통합과 정식 결과 저장을 분리하는 조건이다 |
| Q2. 구조 유지인가 | 기존 골격·상세·업무·신고서를 유지한다. 읽기 모델, 단계 표현, 알림 생성 책임만 수정한다 |
| Q3. Live 연결 방식 | #302 ACK+ledger 결속 chunk→독립 detector→journal/snapshot→기존 FastAPI→공통 목록/상세 |
| Q4. 그래프·인사이트 범위 | 기존 실측 재사용. P0 신규 그래프 없음, P1 처리량/처리 시간 2개와 근거 있는 집계 |
| Q5. 사람의 workflow | 명시적 확인·검토·인지·신고 결정·초안 검토를 각각 저장. 시간·버전·감사 분리 |
| Q6. 시연 구성 | 실제 R1 관측 + 명시적으로 분리한 검증 사례의 대응/Word, 한 운영 화면 사용 |
| Q7. 10/23 필수 | 실제 수락 관측의 목록/상세 반영, 올바른 출처/오류, 독립 알림, 기존 업무 회귀, 영상·증적 |
| Q8. 11/5 우선순위 | R1 근거/정식 결과 연결과 검증, 실제 actor·복구, 집계·UX, 적격 R1 문장화 순 |
| Q9. 줄일 것 | 별도 카드/사이트, 전면 재작성, 가짜 지표, P0 운영 인증·외부 알림·모바일·SSE·R1 LLM 확대 |
| Q10. 인계 인터페이스 | acceptance binding, Run/host/observation identity, v1 DTO, source/provenance/capability, 시간·revision·오류·복구 계약 |

이 결정의 미확인 성립 조건은 최신 원격과 로컬 변경의 통합, 동일 호스트의 spool 접근, 실제 VM smoke, 촬영 사례의 canonical 결속, 선택한 신고서 사례의 현재 버전 재현이다. **이 조건을 아직 완료됐다고 간주하지 않는다.** 실패하면 정한 축소 시연으로 전환하고, 검증되지 않은 기능을 UI로 성공처럼 보이게 만들지 않는다.
