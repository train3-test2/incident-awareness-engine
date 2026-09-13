# Hayabusa Fast Detection Hello World — 실행 기록

## 목적과 근거

Issue #43의 샘플 EVTX → Hayabusa → 탐지 hit 최소 경로 검증 기록을 저장소에 보존한다.
근거는 작성자가 2026-09-07에 남긴 [실행 결과 댓글](https://github.com/train3-test2/incident-awareness-engine/issues/43#issuecomment-5573425134)이다.
이 문서는 기존 기록을 옮긴 것이며 새로운 실행 또는 독립 재검증 결과가 아니다.

## 기존 기록에서 확인한 내용

- 엔진: Hayabusa v4.0.0
- 명령: `dfir-timeline`
- sample EVTX 입력, 실행 및 결과 CSV 생성 성공 보고
- Sigma 계열 탐지 hit 확인 보고
- 확인한 출력 필드: `Timestamp`, `RuleTitle`, `Level`, `Computer`, `EventID`, `RecordID`, `RuleID`

| 예시 hit 필드 | 기록된 값 |
| --- | --- |
| RuleTitle | Suspicious Execution of InstallUtil Without Log |
| Computer | PC-01.cybercat.local |
| EventID | 1 |
| RuleID | 8a426c90-2756-5390-dae9-c5e2e734c96e |
| Timestamp | 미확인 — 기존 댓글에 실제 값 없음 |

RuleID는 당시 Issue 댓글에 기록된 값을 그대로 보존한다. 당시 ruleset artifact가 없어
현재 공개 Rule과의 동일성 및 제목·ID 대응을 독립적으로 검증하지 않았다.

## 재현 정보의 한계

원 댓글에는 입력 파일명·SHA-256, 전체 command/options, ruleset/config 버전,
출력 CSV artifact와 실제 Timestamp·RecordID 값이 없다. 이 문서는 해당 값을 추정해서
채우지 않으며 완전한 재현 패키지로 사용하지 않는다. 실행 기록 보존과 재현 가능성 검증은
구분한다. Timestamp 필드가 있었다는 보고만으로 실제 탐지 시각 검증이 완료됐다고
해석하지 않는다. 원본 CSV·EVTX·실행 설정을 확보할 수 있으면 실제 Timestamp와
Rule identity를 대조하는 것은 후속 확인 사항이며, 추정값을 보충하지 않는다.

`Hayabusa v4.0.0`은 과거 실행 댓글에 보고된 버전이다. 현재 팀 공통 실행환경의
버전을 확인한 결과가 아니므로 이 기록만으로 `configs/toolchain_registry.yaml`의
`hayabusa.version`을 갱신하지 않는다. 해당 실행의 RunMetadata도 이 문서의 근거 자료에
없으므로 Registry Version 연결을 소급 생성하지 않는다. 실제 실행환경의 버전 확인과
Registry/RunMetadata 연결은 qualifying policy 승인 여부와 무관하게 수행할 후속 작업이다.

## 해석과 역할 경계

이 결과는 샘플 로그에서 엔진과 출력 필드를 확인한 Hello World 기록이다.
정상/pilot FP 검증, qualifying policy 승인, detector set 동결 또는 프로젝트 Recall/TTSD
평가 결과를 뜻하지 않는다. 위 예시 Rule을 canonical Fast detector로 채택하지 않는다.

`Computer`는 원본 host 정보다. canonical `entity_id` 매핑과 `DetectionResult` 생성은
역할 3 Fast Adapter의 책임이며, 역할 5는 공통 FastHitRecord의 native 정보를 보존한다.
`FastHitRecord.timestamp`의 목표 형식은 공통 결과 계약
[`result-contracts.md` §2-1](../schema/result-contracts.md)의 UTC ISO 8601 밀리초 표기다.
보존된 기록에는 실제 Timestamp와 전체 command/options가 없으므로 당시 Hayabusa의
출력 시각 형식은 미확인이다. 목표 계약 준수가 당시 실행에서 검증됐다는 뜻은 아니다.
기존 댓글의 `event_v0.host_id` 표현은 당시 계획 기록이며 이 문서에서 새 매핑 규칙으로
확정하지 않는다.

후속 후보 조사·정책 초안은 #44, FastHitRecord 변환은 #45, Platform 연동은 #46에서
별도로 관리한다. 이 문서의 대응 이슈는 #43 하나다.

## Issue #43 종료 범위

이 PR에서 종료하는 범위는 기존 Hello World 실행 보고의 저장소 문서화와 검증 한계의
명시다. 누락된 Timestamp·artifact 복원 또는 독립 재현 검증 완료를 의미하지 않는다.
향후 자료 확보 시 수행할 원본 대조와 실제 실행환경 버전 기록은 미완료로 남긴다.
