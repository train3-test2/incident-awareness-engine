# Fast development episode와 관측 범위

`detection.fast_episodes.build_development_episodes()`는 검증된 selection handoff와
생산자의 coverage 기록을 받아 기존 `FastEpisodeStarts` 및 hit membership provenance를 반환한다.
성능평가 승인이나 최종 정책 동결을 의미하지 않는다. 지표 계산은 수행하지 않는다.

## 개발용 정책

`DevelopmentEpisodePolicy`는 development-only이며 inactivity_gap_sec를 필수로 받는다.
기본 운영값은 없다. 호출 전에 사용할 값을 별도 채택 기록에 남긴다.
`policy_version=fast-development-episodes-v2`, `grouping=run_entity_alert_key`를 사용한다.
이전 v1 산출물을 v2로 이름만 바꾸지 않으며, 새 정책으로 다시 생성해야 한다.
v2 정책은 `(run_id, entity_id, alert_key)`별로 hit를 묶는다.
전체 hit를 timestamp/rule_id/hit_id 순으로 정렬하되 직전 hit 시각은 alert_key별로 유지한다.
첫 hit가 episode를 열고, 직전 hit 이후 간격이 설정값 이상이면 새 episode를 연다.
간격이 같은 경계도 새 episode다. 서로 다른 alert_key는 합치지 않으며, 동일 alert_key의 서로 다른 rule은 함께 묶는다.
Run마다 상태를 초기화한다. reference_time이나 공격 label은 grouping에 사용하지 않는다.
관측 범위 밖 hit는 잘라내지 않고 오류로 처리한다. 이 정책은 Fusion ACTIVE/해제 정책과 다르다.
버전에 gap 값을 포함하므로 평가 계획에서 다른 gap의 입력을 구분할 수 있다.

## Coverage v2: 실제 증적 기반의 제한된 offline 검증

`fast-development-coverage-v2`는 `development-interface-only` 입력이다.
과거 collection_complete/scan_complete 및 숫자형 parse_error_count=0 주장은 받지 않는다.
Hayabusa가 숫자형 카운터를 제공하지 않으므로 parse_error_count는 명시적 null만 허용한다.
이는 오류 허용이 아니다. stderr·보고된 오류·실패 종료·처리 건수 불일치는 거부한다.

필수 입력:
- run/entity, UTC 밀리초 observation_start/end, source/CSV/config 해시
- collection_basis=declared-export-window-and-validator 및 수집 검토·validator 증적 경로/해시
- 원본 metadata, manifest, JSONL, 진단 실행 기록, stdout/stderr, 엔진·룰의 경로/해시
- 호출자가 별도로 고정한 coverage JSON 해시

검증기는 모든 증적의 실제 바이트 해시를 검증한다. metadata의 Run/entity/범위를 대조하고
manifest가 EVTX와 JSONL 해시를 포함하는지 확인한다. 실제 명령의 source/output/engine/rule도
대조한다. verbose·checksum 검증은 필수이며 quiet-errors와 추가 시간/EID 필터는 거부한다.
원본 JSONL을 재파싱하여 stdout의 Total events 및 실행 기록 건수와 대조한다.
진단 CSV와 기존 handoff CSV가 동일해야 하며 기존 selection 검증도 다시 수행한다.
현재 지원하는 명령 형태는 단일 rule 파일의 dfir-timeline이다.
두 번째 토큰은 dfir-timeline이어야 하며 -w/--no-wizard를 필수로 받는다.
-f/-r/-o는 각각 한 번, 경로 인자와 함께 지정해야 한다. 중복 옵션과 미지원 인자는 거부한다.
selection 이후 다시 읽은 handoff의 input/output 및 trace 해시를 audit와 대조하여
서로 다른 snapshot으로 grouping하는 것을 차단한다.

수집 증적의 해시는 고정하지만 자유 형식 validator 보고서의 내용 자체를 자동 판독하거나
생산자의 진실성을 인증하지 않는다. 호출자는 collector/validator의 의미와 실제 Run에 대한
적용 여부를 검토한 뒤 coverage pin을 고정해야 한다. 이것은 lossless OS telemetry 보증이 아니다.

Pair-003~005 collector는 Sysmon EID 1·3에 대해 System.TimeCreated 기반
Run 시작−10초부터 export 시점까지를 조회했다. metadata end는 export 직전 Target 시각이다.
EventData.UtcTime과 필터 시간은 별개이며 context/후속 hit가 범위를 벗어나면 오류 처리한다.
제공된 export 전체의 offline 스캔 증적만 인정하며 실제 온라인 탐지 지연을 뜻하지 않는다.

## 평가 연결과 제한

반환된 FastEpisodeStarts는 StoredRunResults.fast_episodes와 같은 형식이며 정책 버전은
EvaluationPlan.fast_episode_policy_version에 맞춘다. 반환 provenance에 policy, coverage,
selection audit, episode별 hit membership을 보존한다.

공식 평가 소비 경계는 purpose=performance에서 fast-development-* 정책을 거부한다.
이는 최소 가드이며 명시적 정책 목적·승인 상태 검증은 후속 계약 확장으로 남긴다.
FastEpisodeStarts 자체에는 사용 제한 필드가 없으므로 단독으로 공식 평가에 전달하지 않는다.
provenance의 development-only 제한 및 dataset usage 경계를 함께 유지해야 한다.
이 생성기는 공식 성능평가 적격성이나 전체 평가 통과를 승인하지 않는다.
역할1 development-only 산출물의 TTSD/성능 주장 금지도 유지한다.

이번 development 실행은 별도 채택 기록의 60초 gap을 사용한다. 이는 최적화 결과나
최종 freeze가 아니며 현재 0~1 hit/Run 자료만으로 간격값의 적절성을 평가할 수 없다.
환경값과 원본 증적은 repository 밖 또는 로컬 artifacts에 보존한다.
