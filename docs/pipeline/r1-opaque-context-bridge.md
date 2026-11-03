# R1 opaque context bridge v0.1

`incident_awareness.pipeline.r1_opaque_context_bridge`는 Role4 WMI opaque context
supplement를 Role2 opaque Feature 어댑터(`r1_opaque_features`)에 연결한다.
WMI offline preliminary 평가 전용이며 Evidence·Feature 계산은 바꾸지 않는다.

## 두 형식의 구분

| 형식 | 식별 | 구조 |
| --- | --- | --- |
| Role4 supplement | `schema: r1-opaque-item-context-v0.1` | `opaque_id`, `canonical_telemetry{...}`, `authoritative_observation{...}`, `approved_policy{...}`, `source_provenance_receipt_id`, `evaluation_package`, `usage_limits` |
| Role2 어댑터 context | `schema_version: r1-opaque-item-context-v0.1` | `expected_item_ids`, 평면 item 필드 |

두 형식은 같은 schema ID를 쓰지만 구조가 다르다. bridge는 두 계약을 바꾸지 않고
Role4 형식을 별도 모델로 검증한 뒤 `CONVERSION_RULES`의 필드만 옮긴다.
`timezone`, `time_domain`, `approved_policy.config_hash/lifecycle`, receipt는 변환하지 않고
config·receipt와 대조해 bridge manifest에 기록한다.

## 입력과 검증

```bash
uv run python -m incident_awareness.pipeline.r1_opaque_context_bridge \
  --config extraction-config.json \
  --supplement wmi-opaque-context-supplement-v1.zip --supplement-sha256 <sha> \
  --evaluation-package EC-delivery-<id>.zip --evaluation-package-sha256 <sha> \
  --output-dir <new-dir>
```

- supplement: ZIP SHA, 정확한 member 집합, 내부 SHA256SUMS, 정의 외 필드 거부
- 평가 패키지: 호출자가 준 SHA와 context·receipt 선언값 대조, 검증한 바이트에서만 읽기,
  중복 member와 위험한 경로 거부, `consumer-index.json`과 telemetry member만 접근
- expected item: `consumer-index.json`의 `opaque_id` 목록. canonical JSON SHA를 context와 대조하고
  context·receipt·index 집합의 중복·누락·추가를 모두 실패로 기록한다.
  index item에 label·run_type·run/pair ID 키가 있으면 거부한다.
- item: WMI family, `UTC`와 `private_deterministic_offset`, policy ID·version·config_hash·lifecycle,
  `RAW-002`, host·source·channel, 경계 순서, receipt ID·raw_log_id 결속

하나라도 실패하면 어댑터를 호출하지 않고 `bridge-manifest.json`에 실패만 남긴다.
통과하면 `adapter-context.json`을 쓰고 기존 어댑터를 호출한다. 어댑터 실패도 묶음 전체를 막는다.

## 신뢰 경계

bridge manifest는 독립 검증 항목(`independently_verified`)과 Role4 receipt를 신뢰한 항목
(`trusted_role4_receipt`)을 나눠 기록한다. source-chain commitment의 원문, RAW-001→RAW-002
결속, position proof, host verification, 균일 시간 이동은 봉인 감사 범위이며 bridge가 독립
검증하지 않는다. 관측 경계는 제공된 private offset 시간 영역 안에서만 쓴다.

## 비범위

모델 학습·추론·채점, threshold, Temporal Replay, causal/online/TTSD, holdout 주장은 하지 않는다.
실제 평가 패키지는 Role5의 평가 경로 동결과 후보 접근 승인 이후에만 사용한다.
