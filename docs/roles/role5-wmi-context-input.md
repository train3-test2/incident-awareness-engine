# 역할5 WMI context 입력 검증

`evaluation.context_inputs.validate_context_inputs`는 #256의 역할5 context 검증 경계다.
기존 loader로 읽은 `R1EvidenceArtifactRun`, 실제 NormalizedEvent batch,
metadata의 run_id/target_host/start_time/end_time을 전달한다.

검증은 context의 존재·Run/host 일치·Run 시작 이전 시각, Event ID 중복,
직접 Evidence의 Run 범위와 context 미포함을 확인한다. 성공 시 정렬된 context ID tuple을
반환하며 이를 특징이나 점수에 더하지 않는다. 오류를 miss로 바꾸지 않는다.
run_start와 같은 이벤트는 context가 아니며 run_end와 같은 이벤트는 허용한다.

호출자는 **추출 전에** timestamp > run_end 이벤트를 제거하고 run_start를 selector에 전달해야 한다.
이 helper는 post-Run 입력을 거부하지만 사후 검증만으로 추출 전 필터링을 대신하지 않는다.
계보의 구조적 정확성은 기존 selector/extractor 책임이며 helper는 이를 재구현하지 않는다.
원본 hash와 artifact 로딩, 실제 관측 coverage도 호출자가 확인한다.

이 함수는 아직 production runner에 자동 연결되지 않았다. 실제 WMI 입력 수령 시
loader 이후 Baseline 특징 생성 전에 호출한다. 합성 WMI Normal/Attack으로 검증했으며
실제 Pilot 성공이나 causal 적격성을 주장하지 않는다.
available_at/watermark, TTSD, 운영점 선택은 범위 밖이다.

이슈 #259의 reference 정본은 r1-wmi-a01-reference/wmi-ref-v0.1이며 후보 구간은
A01 invoked_at_utc부터 +2초까지 양끝 포함이다. 이전 ±2초 제안은 사용하지 않는다.

Run 시작·종료 경계는 UTC 밀리초 정밀도여야 하며 서브밀리초 값은 거부한다.
Completed artifact라도 selector가 `selected`가 아니거나 lineage provenance가 없으면
검증 실패다. 정상 선택된 lineage의 `context_event_ids`가 비어 있는 경우는 허용한다.
추출 summary의 `input_event_count`와 전달된 Event batch 크기도 일치해야 한다.
이는 입력 동일성의 최소 검사이며, 같은 수의 Event 교체나 전체 내용의 동일성을 보증하지 않는다.
