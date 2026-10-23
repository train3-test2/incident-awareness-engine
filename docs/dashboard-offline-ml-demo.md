# 역할 5 Offline ML v0.2 시연 화면

검증일: 2026-10-20 (Asia/Seoul). 실행 중인 8794 Dashboard의 기존 정적 자산 경로를 사용한다.
서버 재시작 없이 운영 View 상단 **Offline ML 분석** 링크로 진입한다.

- 화면: <http://127.0.0.1:8794/dashboard-assets/offline-ml.html>
- 분석 유형: **Offline Development Static ML**
- 출처: 역할 5 전달 `role5-demo-handoff-20261019-v0.2.zip`의 현재 모델 및 저장된 출력.
- 원본 ZIP은 사용자 문서 영역에서 읽었으며 저장소나 정적 자산 폴더에 복사하지 않았다.

## 패키지 및 데이터 검증

외부 `role5-demo-handoff-20261019-v0.2.zip.sha256`과 ZIP SHA-256이 일치했다.

```text
1aa9690adc6f583f8e68fa095b2147303d543e1896dd932759f72b208e1c7a0c
```

내부 `SHA256SUMS.txt`에 기재된 **17개 파일 모두 일치**했으며 누락·중복·미기재 구성 파일이
없는 것을 확인했다. README, manifest, demo-config, 현재 model, training/check 입력,
training-predictions, pair008-report 및 reproduce.py의 존재를 확인했다. 패키지 코드는 실행하지 않았다.

모델 파일 SHA-256은 manifest와 pair008-report 모두와 일치한다.

```text
7170c3797244216c5693c0504de657c51a0512929c9d3303dce697875158b006
```

결과의 `model_sha256`은 파일 바이트 해시와 다른 **canonical JSON 해시**이다. 이를 실제 모델의
canonical JSON과 대조했고, 결과의 `input_sha256`도 대응 FeatureRow와 대조했다. 학습 데이터
해시는 sample_id 정렬과 label을 포함하며, 예측 입력 해시는 원래 행 순서와 label 제외 계약을 따른다.
UI는 파일 해시와 canonical 해시를 구별한다. 모델 계수 재학습이나 추가 추론은 하지 않았다.

| 원본 Run | 구분 | Feature 값 | 저장된 P(label=1) | training_overlap |
| --- | --- | --- | --- | --- |
| RUN-20261016-928 | Pair-008 개발 확인 | [1, 1] | 0.63392845650396 | false |
| RUN-20261016-929 | Pair-008 개발 확인 | [0, 1] | 0.36607154346309795 | false |

모델: `remote-management-preliminary-v0.1`.
Feature Version: `development-whole-observation-presence-v0.1`.
Feature Scope: `whole_observation_binary_presence`.

Feature 순서:

1. `remote_session_process_lineage_deviation`
2. `remote_process_network_follow_on`

학습 Run은 `RUN-20261008-915`, `916`, `917`, `918`, `919`, `920`의 6개이다. 선택 목록에서
Pair-008 두 사례와 별도 그룹으로 제공하며 학습 사례는 `training_overlap=true`를 표시한다.
manifest·모델 plan·입출력의 Run 집합을 대조했고 학습/확인 집합이 겹치지 않는다.
8개 Run 전체를 재학습하지 않았다.

## 운영 분석과의 분리

이 화면은 PostgreSQL이나 기존 Run API를 사용하지 않는다. 원본 R1 Run은 현재 운영 DB에 없으며
가짜 Run을 추가하지 않았다. 별도 선택기는 패키지의 원본 Run ID만 사용한다.
S0 `RUN-20261019-006/007`에는 확률이나 새 metadata를 붙이지 않는다.
FusionResult, DetectionResult, DecisionResult, DEMO_RULE_MATCH, Replay Score와 섞지 않는다.

로컬 CLI가 비공개 ZIP을 검증한 후 **허용된 필드만** 작은 표시 JSON으로 내보낸다.
브라우저는 이 표시 JSON 한 개만 읽고, 사례 전환 시 추가 API를 호출하지 않는다.
검증 실패나 필수 계약 불일치 시 결과 영역을 표시하지 않는다.

다른 로컬 환경에 준비할 때는 저장소 루트에서 다음을 실행한다. ZIP 경로는 실제 비공개 파일을
지정하며 `.sha256` 파일은 기본적으로 ZIP 바로 옆에서 읽는다.

```powershell
$env:PYTHONPATH = Join-Path (Get-Location) 'src'
.\.venv\Scripts\python.exe -m incident_awareness.dashboard.offline_ml_package '<private-package.zip>'
```

생성 파일은 `src/incident_awareness/dashboard/ui/assets/offline-ml-data.local.json`이며 gitignored이다.
원본과 표시 export는 별개다. 새 패키지를 선택하면 검증 CLI를 다시 실행하고 화면을 새로고침한다.
현재 실행 서버에는 새 API 등록이나 재시작이 필요 없다. 패키지가 준비되지 않은 환경에서는
결과를 임의 생성하지 않고 준비 상태 안내를 표시한다.

## 민감 정보 비노출

- ZIP·README·reproduce.py·원본 모델/입력 JSON·provenance 전체는 정적 자산으로 제공하지 않는다.
- 공개 필드는 Run ID, 모델/Feature 버전, Feature 값, 기존 확률, overlap, 해시 및 null 계약뿐이다.
  manifest의 임의 문자열, 내부 경로, 원본 provenance, 과거 실행 보고서, smoke score는 내보내지 않는다.
- 공개 문자열에는 식별자 패턴을 적용한다. 화면은 `textContent`로 표시한다.
- 실제 ZIP의 경로 후보 27개와 공개 JSON을 대조해 비노출을 확인했다. 경로 원문은 검증 보고서에도 기록하지 않았다.
- 원본 ZIP, provenance/usage-record.json, model/model.json, inputs/training-rows.json,
  reproduce.py의 정적 URL은 모두 404였다. 이는 별도 음성 접근 검사이며 정상 화면의 HTTP 오류와 구분한다.
- 공개 JSON이 검증기의 허용 필드 출력과 정확히 일치했다. 원본 ZIP의 최종 해시도 최초 값과 동일하다.

## 검증 결과

- Python **1,417 PASS**: Dashboard UI/API, 업로드, Devtools, Pipeline/Standalone/Worker,
  Storage 및 UI CI 목록 계약. 신규 패키지 검증·변조·계약 오류·비공개 필드 제거 검사 포함.
- Node UI **505 PASS**: 전체 기존 UI와 Offline 데이터 로딩·null 보존·학습/확인 분리·오류 차단.
- `ruff check .`, `ruff format --check .`, `git diff --check` PASS.
- 실제 Chromium: 운영 화면에서 링크 이동, Pair-008 두 사례의 모든 자릿수와 Feature,
  학습 사례 전환, 모델/Feature Version, null 계약, 해시 출처, 계약 불일치 차단 및 복구 확인.
  데스크톱과 390px 모바일에서 가로 넘침 없음. 콘솔·JavaScript·HTTP·연결 오류 0건.
- 기존 S0 006/007: 각각 67-point, Trace 최대 0.5/1.0, Episode 0/1, Threshold 0.8/0.4,
  FEP-001 및 실제 기여 ID 2개, Evidence 아카이브 없음, Fast not_evaluated,
  Hybrid t_e/decision_path null, Stage Timing no_stage_timings 유지.
- 기존 Run 선택, Metadata 필터, 5초 갱신, 자동 추적 설정, 업로드 UI 활성화,
  Runtime 및 Telemetry 조회 유지. 이번 검수에서 신규 업로드로 DB 행을 추가하지 않았다.
- DB 모든 테이블의 행 해시·OID·컬럼·제약·인덱스·트리거가 검수 전후 동일했다.
  Run 7개, Event 1,788개 그대로다. Dashboard PID 10312와 기존 LocalStack 컨테이너 유지.
- 서버/컨테이너 종료, DB 변경, 실제 AWS 호출, Git 변경 이력 생성은 수행하지 않았다.

검증 원문과 화면 캡처는 gitignored `build/offline-ml/`에 있다.
`package-verification.json`, `browser-results.json`, `preservation.json`,
`python-tests.log`, `ui-tests.log`, Pair-008 데스크톱/모바일 캡처 및 `s0-regression/`을 참조한다.

## 변경 파일

| 파일 | 용도 |
| --- | --- |
| `src/incident_awareness/dashboard/offline_ml_package.py` | ZIP·계약 검증 및 비공개 필드를 제외한 로컬 export |
| `src/incident_awareness/dashboard/ui/assets/offline-ml.html` | 별도 사후 분석 화면 |
| `src/incident_awareness/dashboard/ui/assets/offline-ml.js` | 사례 선택·저장된 값·출처 표시 |
| `src/incident_awareness/dashboard/ui/assets/offline-ml-contract.mjs` | 표시 데이터 로딩·계약 검사 |
| `src/incident_awareness/dashboard/ui/assets/offline-ml.css` | 기존 디자인 토큰을 쓰는 최소 스타일 |
| `src/incident_awareness/dashboard/ui/dashboard.html` | 상단 링크 1개 |
| `.gitignore` | 생성 표시 JSON 및 임시 파일 제외 |
| `.github/workflows/ci.yml` | 신규 UI 테스트 1개를 기존 목록에 추가 |
| `tests/dashboard/test_offline_ml_package.py` | 무결성·변조·분리·비노출 검사 |
| `tests/dashboard/ui/test_offline_ml_contract.mjs` | UI 데이터 계약 검사 |
| `tests/dashboard/api/test_dashboard_view.py` | 기존 정적 경로와 DB 없는 독립 화면 검사 |
| `docs/dashboard-offline-ml-demo.md` | 본 검증 및 촬영 안내 |

기존 미커밋 작업은 보존했다. 생성된 로컬 표시 JSON은 제품 소스나 원본 패키지가 아니며 Git에 추가하지 않는다.

## 촬영 설명과 한계

화면에 다음 안내를 명시한다.

> 보정되지 않은 P(label=1) 출력입니다. 실제 공격 확률, 확정 탐지, 공식 성능평가 또는 TTSD 결과가 아닙니다.

`classification_threshold`, `formal_performance`, `TTSD`는 모두 원본의 null을 유지한다.
보정 정보는 제공되지 않았으며 출력 의미는 패키지의 uncalibrated 계약에 근거한다.
Pair-008은 학습 데이터와 겹치지 않는 개발 확인 사례이지만 공식 unseen Holdout 평가가 아니다.
전체 관측 구간의 Feature이므로 확률을 시간별 Fusion Replay나 탐지 시점으로 설명하지 않는다.
원본 Event/Evidence부터 재추출하는 검증은 이번 전달물 범위 밖이다.
S0의 Fast 미평가와 Hybrid t_e null도 그대로이며 이 패널이 이를 확정하지 않는다.
