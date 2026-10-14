# Fast development episode와 관측 범위

`detection.fast_episodes.build_development_episodes()`는 검증된 selection handoff와
생산자의 coverage 기록을 받아 기존 `FastEpisodeStarts` 및 hit membership provenance를 반환한다.
성능평가 승인이나 최종 정책 동결을 의미하지 않는다. 지표 계산은 수행하지 않는다.

## 개발용 정책

`DevelopmentEpisodePolicy`는 development-only이며 inactivity_gap_sec를 필수로 받는다.
기본 운영값은 없다. 호출 전에 사용할 값을 별도 채택 기록에 남긴다.
동일 Run/entity의 모든 qualifying rule hit를 timestamp/rule_id/hit_id 순으로 정렬한다.
첫 hit가 episode를 열고, 직전 hit 이후 간격이 설정값 이상이면 새 episode를 연다.
간격이 같은 경계도 새 episode다. 다른 rule의 hit도 같은 entity 내에서는 묶는다.
Run마다 상태를 초기화한다. reference_time이나 공격 label은 grouping에 사용하지 않는다.
관측 범위 밖 hit는 잘라내지 않고 오류로 처리한다. 이 정책은 Fusion ACTIVE/해제 정책과 다르다.
버전에 gap 값을 포함하므로 평가 계획에서 다른 gap의 입력을 구분할 수 있다.

## Coverage 계약

FastScanCoverage JSON 및 외부에서 고정한 SHA-256을 전달한다.
run_id/entity_id, observation_start/end, 원본 파일·CSV·config SHA-256,
collection_complete=true, scan_complete=true, parse_error_count=0, exit_code=0,
producer_record(생산자 검증 근거 위치)를 필수로 받는다.
UTC 밀리초 관측 범위는 호출자가 제공한 실제 Run 범위와 정확히 일치해야 한다.
기존 select_fast_hit로 CSV/config/handoff/selection 의미를 다시 검증한다.

해시는 변조 확인 수단이며 생산자의 진실성이나 수집 완전성을 인증하지 않는다.
생산자 기록은 실제 collection/scan 로그 검토 후 작성해야 한다. metadata의 시작·종료,
빈 CSV 또는 exit 0만으로 complete=true를 만들어서는 안 된다.
전체 관측이 증명된 경우에만 hit가 없는 Run의 빈 episode 목록을 반환한다.

## 평가 연결과 제한

반환된 FastEpisodeStarts를 StoredRunResults.fast_episodes에 연결한다.
정책 버전은 EvaluationPlan.fast_episode_policy_version과 일치시켜야 한다.
membership provenance, coverage 원문/해시, selection audit도 함께 보존한다.
FastEpisodeStarts 자체에는 사용 제한 필드가 없으므로 provenance의 development-only
제한과 dataset usage 경계를 유지해야 한다. 이 함수만으로 공식 평가 적격성을 승인하지 않는다.

현재 보유 915~920의 기존 실행 묶음은 전체 qualifying hit까지 검증됐지만 별도의
coverage 생산자 증명과 episode gap 채택 기록은 아직 없다. 임의의 coverage나 정책값을
채워 공식 산출물로 만들지 않는다. 역할1 development-only 산출물의 TTSD/성능 주장 금지도 유지한다.
