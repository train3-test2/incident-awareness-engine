# MonoRouter Grounded Report 초안 연결

후속 타임라인·원클릭 인지 기록·LLM 상태 구분·PDF는
[Human Workflow / Report UX 개선 기록](workflow-report-ux.md)을 참조한다.

검증일: 2026-10-20 (Asia/Seoul). `feature/dashboard/demo-polish`의 기존 미커밋 변경과
8794/8795 서버, LocalStack, PostgreSQL 데이터·스키마를 보존했다. commit/push/PR은 수행하지 않았다.

## 실제 외부 호출 결과

코드에 정의한 합성 fixture **1건**을 명시적으로 활성화한 개발 프로세스에서 호출했다.
기존 S0 Run이나 실제 Raw Sysmon/조직정보/개인정보를 사용하지 않았다.

| 항목 | 검증 결과 |
| --- | --- |
| Endpoint | `https://monogpt.kr/api/monorouter/v1/anthropic/v1/messages` |
| Client | Python `requests` |
| Protocol | Anthropic 호환 Messages, `anthropic-version: 2023-06-01` |
| HTTP | 200 |
| 요청 모델 | `claude-haiku-4.5` |
| 실제 응답 모델 | `claude-haiku-4-5-20251001` |
| 요청 시각 | 2026-10-20 15:23:16.831 KST (`06:23:16.831444+00:00`) |
| 완료 시각 | 2026-10-20 15:23:20.950 KST |
| 토큰 | input 573 / output 307 / cache creation 0 / cache read 0 |
| 출력 검증 | 출력 계약·필드 값·Evidence ID와 코드 소유 합성 원천 사실 일치 |
| 결과 | `monorouter_grounded` 개발 초안, `not_submitted` |

API 키는 사용자가 지정한 저장소 밖 `D:/Dev/config.yaml`에서 읽어 **테스트 프로세스 환경변수에만**
주입했다. 키 값은 명령행·코드·Git·stdout·브라우저에 넣지 않았다. 안전한 호출 증적은
`build/monorouter-integration/live-result.json`과 해당 디렉터리의 `live.sqlite3`에 있다.
키 값이 원장·서버 로그·Dashboard/OpenAPI 응답에 없는지 별도로 검사했다.

## 서버 설정과 활성화 조건

기본은 외부 호출 비활성이다. `APP_ENV=development`와 `IAE_MONOROUTER_ENABLED=1`이 **동시에**
명시돼야 외부 호출을 고려한다. 추가로 입력 전체가 서버 코드의 합성 fixture와 정확히 일치해야 한다.
브라우저의 `synthetic=true`, Run label, caller가 붙인 VERIFIED 표시는 허용 근거가 아니다.

| 환경변수 | 기본값 / 용도 |
| --- | --- |
| `APP_ENV` | 기존 `local`; 외부 호출에는 정확히 `development` 필요 |
| `IAE_MONOROUTER_ENABLED` | `0` |
| `IAE_MONOROUTER_ENDPOINT` | 위 검증된 Messages Endpoint |
| `IAE_MONOROUTER_MODEL` | `claude-haiku-4.5` |
| `IAE_MONOROUTER_RESPONSE_MODEL` | `claude-haiku-4-5-20251001` |
| `IAE_MONOROUTER_CONNECT_TIMEOUT` | 3초; 허용 범위 0초 초과~10초 |
| `IAE_MONOROUTER_READ_TIMEOUT` | 25초; 허용 범위 0초 초과~45초 |
| `IAE_MONOROUTER_MAX_TOKENS` | 1200; 1~4096 |
| `IAE_MONOROUTER_API_KEY` | 서버 프로세스에서만 주입, 기본 공란 |
| `IAE_REPORT_STORE_PATH` | 기본 `build/grounded-reports/drafts.sqlite3` |

Endpoint는 환경 설정으로 분리하되 현재 검증된 HTTPS host/path만 허용한다. URL credential,
query string, fragment와 다른 host는 거부한다. 키 오발송 방지를 위해 redirects와 환경 proxy/netrc,
자동 재시도를 사용하지 않으며 TLS 검증을 유지한다. 입력 24 KiB, 응답 128 KiB 한도를 둔다.
Timeout은 Requests의 connect/read timeout이다. read timeout은 전체 요청의 엄격한 wall-clock
deadline과 동일하지 않으며, 추가로 응답 chunk를 받을 때 경과시간도 검사한다.

합성 호출 재검증 예시(키 값은 입력하거나 출력하지 않는다):

```powershell
$env:PYTHONPATH='src'
$env:APP_ENV='development'
$env:IAE_MONOROUTER_ENABLED='1'
.venv/Scripts/python.exe scripts/dev/check_monorouter.py --live --config-file D:/Dev/config.yaml
```

`--live`가 없으면 위 환경변수와 무관하게 외부 호출을 끄고 합성 fixture의 fallback을 검증한다.
CLI는 기존 Run이나 Raw 파일을 입력받는 옵션을 제공하지 않는다. stdout에는 메타데이터와
검증 결과만 출력하며 credential/provider 예외의 원문을 출력하지 않는다.

## Human Workflow와 API/UI

기존 `build_report_input`으로 DB에서 Grounded Report 입력을 만들며, **현재 `proceed` 결정이
있는 경우에만** 초안을 생성한다. 근거 검토·알림 확인·신고 진행 결정의 기존 전이를 재사용한다.
초안 생성은 확인·인지시각·신고 완료 기록을 새로 만들지 않는다. `t_h`를 추정하지 않는다.

| API | 계약 |
| --- | --- |
| POST `/human-workflow/alerts/{alert_id}/report-drafts` | `expected_version` 정수, UUID `idempotency_key`만 수신 |
| GET `/human-workflow/alerts/{alert_id}/report-drafts` | 최근 50개 초안/진행 상태, 호출 메타데이터, 현재 Workflow와 일치 여부 |

Actor 경계는 기존 제한된 local demo Actor다. 같은 Origin/local Host/loopback을 확인한다.
클라이언트가 API 키·Endpoint·임의 report input·데이터 분류를 전달하면 422다.
진행 결정 없음/버전 충돌은 409, 원천 근거 불충분은 422, 저장소 장애는 503이다.

기존 Workflow 탭에 `신고 검토 초안 생성`, `저장 초안 조회`를 연결했다. 진행 결정 전에는
생성 버튼을 비활성화한다. 생성 중 중복 클릭을 막고, 응답 유실 시 같은 키를 재사용한다.
늦게 도착한 이전 Run/알림/버전 응답을 화면에 적용하지 않는다. 모델 출력은 HTML로 실행하지 않는다.
저장 초안을 다시 읽으면 새로고침 후 복원되며, 결정 변경 후에는 이전 Workflow 버전으로 표시한다.

기존 서버는 재시작하지 않았다. 새 코드 검증용 서버는 **`http://127.0.0.1:8797/dashboard`**이며
`APP_ENV=local`, 외부 호출 비활성으로 실행했다. 기존 8794/8795의 신규 초안 API 반영에는
사용자가 관리하는 재시작이 필요하다.

## 입력·출력·원천 근거 검증

기존 `grounded_report_input_v1`을 재검증한다. 필드 집합은 발생 일시/원인/피해 내용·규모/대응/
담당부서/연락처의 6개다. 실제 Workflow는 현재 완전한 Evidence archive resolver가 없으므로
모두 UNKNOWN을 유지한다. LLM에 보내기 위해 원문이나 조직정보로 보충하지 않는다.

이번 실제 외부 호출의 원천은 `reporting/synthetic.py`의 코드 소유 합성 fixture다. 합성 발생시각과
합성 대응조치만 알려진 값이며, 원인·피해·부서·연락처는 UNKNOWN이다. 합성 Evidence →
source event → `RawLogReference` 관계를 코드에서 고정하며 실제 기존 로그에서 파생하지 않았다.

Provider로 전달하는 allowlist는 합성 필드 값과 Evidence ID, 출력 스키마뿐이다.
Run/Entity/Actor ID, `t_h`, 결정 사유, `raw_ref`, Raw Sysmon은 전송하지 않는다.
실제 Workflow 입력은 활성화 flag가 켜져 있어도 `blocked_data`로 차단하고 로컬 fallback을 사용한다.
실제 데이터 전송을 허용하는 브라우저 옵션이나 우회 환경변수는 이번 단계에 추가하지 않았다.

`grounded_report_output_v1`은 필드 ID/value/Evidence ID만 허용한다. 다음 응답은 거부하고 fallback한다:

- 필드 누락·중복·추가, 자유 서술·요약 등 계약 밖 필드.
- 원천에 없는 원인, 피해 규모, 유출 확정, 임의 Evidence ID.
- UNKNOWN을 확정 값으로 바꾸거나 알려진 원천 사실을 변경한 경우.
- JSON 오류, 비 text block, 잘린 응답, 부적절한 토큰 메타데이터, 미승인 모델 변경.

`조사 중`은 UNKNOWN과 동등하게 정규화할 수 있다. 검증 후에도 원천의 canonical facts를
사용해 고정 Jinja2 템플릿으로 렌더링한다. LLM의 자유 본문을 그대로 표시하지 않는다.
유출 여부는 UNKNOWN/조사 중으로 명시한다. 법적 의무는 UNDETERMINED, 제출 상태는 not_submitted다.

## Fallback과 호출 감사

비활성/개발 환경 아님/키 없음/실제 데이터 차단/설정 오류/Timeout/429/HTTP·연결 오류/
잘못된 응답·출력·모델 변경 시 `jinja2_fallback`을 사용한다. 자동 재시도로 중복 비용을 만들지 않는다.
템플릿은 서버의 고정 plaintext 파일이고 `StrictUndefined`를 사용한다. 사용자/LLM 텍스트를
템플릿 코드로 재해석하지 않는다.

기록하는 호출 정보는 요청/실제 모델, 요청·완료 UTC 시각, HTTP 상태, 검증된 input/output/cache
토큰 수와 고정 상태 코드다. 응답을 받지 못하면 실제 모델·토큰은 null로 유지한다.
모델 버전이 달라졌을 때도 형식이 유효한 모델 정보와 사용량은 감사에 남기고 초안은 fallback한다.
원문 예외·HTTP 응답 body·프롬프트·API key·민감 원문은 기록하지 않는다.

## 영속 저장과 동시 변경

PostgreSQL Migration은 필요 없다. 초안과 안전한 호출 메타데이터는 별도 서버 SQLite 원장에
저장하며 기존 분석/Human Workflow PostgreSQL 테이블을 수정하지 않는다.

원장은 alert ID, Workflow 버전, 신고 진행 action ID, 입력 digest, 생성/완료시각, 상태,
검증된 초안, 안전한 call metadata를 저장한다. 원본 입력/원문 응답/키는 저장하지 않는다.
기존 파일·테이블을 초기화하지 않으며 새 원장의 테이블만 최초 사용 시 생성한다.

`(alert_id,idempotency_key)` UNIQUE로 요청을 예약한 뒤 DB lock을 해제하고 외부 호출한다.
진행 중 중복 요청은 409, 완료된 동일 입력 재요청은 저장 결과로 수렴한다. 같은 키의 다른 입력은
409다. 요청 직전에 safe metadata를 먼저 저장하므로 중간 종료 시에도 요청 중 상태를 남긴다.
그런 불확실한 요청은 자동 재전송하지 않는다.

완료 직전에 PostgreSQL의 현재 진행 결정·버전·입력을 다시 읽는다. 바뀌면 초안을 무효화하며
이미 사용한 토큰 메타데이터는 보존한다. 두 DB 사이의 분산 트랜잭션은 없으므로 완료 직후
결정이 바뀔 수 있다. 조회 시마다 현재 버전과 비교하여 구버전 초안으로 표시하며 자동 제출은 없다.

데모 기본 경로는 gitignored `build/` 아래다. 장기 운영에서는 `IAE_REPORT_STORE_PATH`를
백업·영속 볼륨 정책이 적용된 서버 디렉터리로 지정해야 한다. 기존 PostgreSQL 백업·스키마 정책을
변경하지 않았고 이번 작업에서 기존 DB/volume/server를 삭제·초기화·종료하지 않았다.

## 검증

- 실제 MonoRouter 합성 호출: 1건, HTTP 200, 모델/시각/573·307 토큰 기록, 출력·원천 대조 통과.
- 모의 transport/출력/ledger 검증: 모델 변경 감사 보완 후 37건 통과.
- Dashboard/Report/Pipeline reporting/저장소·CI 목록 Python 회귀: 599건 통과.
- 실제 임시 PostgreSQL: 기존 lifecycle·동시 수정·버전 분리와 초안 gate/영속화 4건 통과.
- Node UI 전체: 512건 통과. 기존 S0 Replay·Offline ML 포함.
- 실제 브라우저: 신고 결정→초안 생성→조회→새로고침 복원. 임시 서버 실제 재시작 후 초안과
  5개 Human Workflow 감사 이력 복원. 외부 요청 0건, JS 오류 0, 390px 가로 넘침 없음.
- 실제 데모 DB: Run 8/Event 1,795/Fusion 8/Decision 8, 기존 행·스키마 보존. 알림 007=1,
  006/008=0, 실제 담당자 행위·`t_h` 생성 0건 유지.
- API 키가 SQLite/서버 로그/브라우저 응답에 없는지 확인. Ruff check/format 및 diff 검사 통과.

증적은 `build/monorouter-integration/`의 `live-result.json`, `python-final.log`, `node-regression.log`,
`browser-real.json`, `browser-isolated.json`, `server-restart.json`과 스크린샷이다.
자동화한 담당자 입력과 서버 재시작은 이번에 생성한 임시 DB/전용 8796 서버에만 적용했다.

## 수정 파일과 남은 작업

새 구현:

- `reporting/config.py`: 환경 설정, SecretStr, 활성화·Endpoint/모델 범위.
- `reporting/monorouter.py`: requests Messages Adapter, 제한된 응답 파싱, 안전한 호출 메타데이터.
- `reporting/contracts.py`, `reporting/synthetic.py`: 출력 계약, 원천 대조, 합성 입력 경계.
- `reporting/service.py`, `reporting/templates/draft.txt.j2`: 생성 orchestration과 Jinja2 fallback.
- `reporting/store.py`: 독립 SQLite 원장, 멱등성, 중단/변경 처리.
- `dashboard/api/report_drafts.py`, `scripts/dev/check_monorouter.py`.
- `tests/reporting/test_monorouter_reports.py`, `tests/dashboard/api/test_report_drafts.py`.

기존 코드에 router 등록(`dashboard/api/app.py`), Workflow UI/Controller·해당 테스트, 기존
PostgreSQL 통합 테스트를 확장했다. `.env.example`, `pyproject.toml`, `uv.lock`에 설정과
requests/Jinja2 의존성을 반영했다. 그 밖의 기존 미커밋 작업은 보존했다.

실제 조직정보·Raw·개인정보 연결은 사용자 승인 전까지 허용하지 않는다. 후속에는 원천 archive
resolver와 무결성 검증, 필드별 최소 전송/비식별 정책 및 승인 기록, 운영 인증·조직별 권한,
장기 원장 보존/백업 정책이 필요하다. 현재 엄격한 값 일치 검증을 완화해 자연어 재서술을 허용하려면
별도의 claim-level 원천 검증 계약이 먼저 필요하다. 실제 KISA 제출 기능은 구현하지 않았다.

구현 참고: [Anthropic Messages 계약](https://platform.claude.com/docs/en/api/typescript/messages/create),
[Requests timeout 의미](https://requests.readthedocs.io/en/latest/user/quickstart/#timeouts),
[Jinja Environment/StrictUndefined](https://jinja.palletsprojects.com/en/stable/api/).
MonoRouter 호환 동작은 위 실제 합성 호출로 별도 확인했다.

[DOCX 출력: 제공된 KISA 원본 양식 기반 Word 신고서](kisa-docx-quality.md).
