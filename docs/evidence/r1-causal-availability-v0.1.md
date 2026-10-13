# R1 causal availability 계약 v0.1

> 상태: implemented / OFFLINE WHOLE-EPISODE ONLY
> 범위: R1 Evidence event-time availability와 #232 Temporal Replay 전달 계약
> 비범위: processing wall-clock latency, incremental selector, Fusion weight·threshold·stopping, TTSD

## 1. 목적과 시간 의미

현재 R1 selector는 전체 `NormalizedEvent` batch를 먼저 materialize한 뒤 terminal 후보 유일성, ambiguity, temporal inversion과 GUID validation을 판정한다. 후속 Event가 앞서 보인 선택을 바꿀 수 있으므로 Evidence의 direct Event time만으로 causal 사용 가능 시각을 정하지 않는다.

시간 의미를 다음과 같이 분리한다.

- `Evidence.timestamp`: `Evidence.event_ids`가 참조하는 direct Evidence Event의 `NormalizedEvent.timestamp` 최댓값
- `available_at`: 미래 Event를 사용하지 않고 해당 Evidence identity와 생성 여부가 더 이상 바뀌지 않는 최초 event-time frontier
- `watermark_at`: 현재 replay 분석 입력에 Event를 더 추가하지 않는다고 선언한 authoritative boundary

v0.1 whole-episode 계약에서는 다음 등식을 사용한다.

```text
watermark_at = authoritative RunMetadata.end_time = run_end
available_at = run_end
watermark_basis = authoritative_run_end
```

이는 event-time replay 계약이다. S3 업로드, normalization, artifact publication 또는 consumer 처리 wall-clock latency를 나타내지 않는다. Watermark는 닫힌 replay 입력을 뜻할 뿐 telemetry completeness를 보장하지 않는다.

## 2. Evidence별 availability

### 2.1 lineage deviation

Lineage deviation의 `timestamp`는 pre-Run context를 제외한 direct lineage Event 중 가장 늦은 시각이다. 그러나 자동 selector가 terminal을 선택하려면 같은 ProcessGuid의 후속 EID 3가 필요하고, whole-episode 범위에서 terminal 후보가 유일하며 temporal inversion이나 GUID validation failure가 없음을 확인해야 한다.

따라서 terminal EID 1 또는 첫 EID 3 시각으로 availability를 앞당기지 않고 `available_at = run_end`를 사용한다.

### 2.2 network follow-on

Network follow-on의 `timestamp`는 EID 1과 EID 3 중 가장 늦은 시각이다. 현재 관계 조건상 실질적으로 EID 3 시각이다. EID 3를 관측하면 extractor의 직접 관계 조건은 완성되지만, 해당 EID 1이 유일한 terminal이라는 selector 결정은 whole-episode close 전까지 바뀔 수 있다.

따라서 network follow-on도 `available_at = run_end`를 사용한다.

`context_event_ids`는 pre-Run lineage reconstruction provenance다. Direct `Evidence.event_ids`와 timestamp에는 포함하지 않으며 availability를 앞당기지도 않는다.

## 3. Authoritative watermark 입력

Builder는 `RunMetadata`를 명시적으로 입력받고 다음을 요구한다.

- `RunMetadata.end_time`이 non-null인 completed Run boundary
- `run_start <= run_end`
- Evidence artifact와 `RunMetadata.run_id` 일치
- Evidence `entity_id`와 `RunMetadata.target_host` 일치
- 모든 `Evidence.timestamp <= run_end`

`run_end`는 Evidence timestamp, `max(event.timestamp)` 또는 extraction summary 값에서 추론하지 않는다. 기존 repository가 검증한 trusted `RunMetadata` 또는 동등한 authoritative Run boundary에서 전달한다.

## 4. Causal availability envelope

`src/incident_awareness/pipeline/r1_causal_availability.py`는 기존 artifact를 수정하지 않고 `R1CausalAvailabilityEnvelope`를 만든다.

Run-level 필드는 다음을 포함한다.

- contract version, `run_id`, `entity_id`
- `run_start`, `run_end`, `watermark_at`, `watermark_basis`
- selector policy ID/version/config hash
- approved lineage policy ID/version/config hash
- source extractor version, Evidence count
- source Evidence JSONL과 extraction summary SHA-256

Evidence-level availability record는 다음을 포함한다.

- `evidence_id`
- 기존 `Evidence.timestamp`
- `available_at`
- direct `event_ids`
- 선택 lineage의 `context_event_ids`

Builder는 먼저 기존 `load_r1_evidence_artifacts()`를 호출해 Evidence artifact 무결성과 summary binding을 검증한다. 그 후 caller가 전달한 selector/approved policy identity와 summary provenance가 정확히 일치하는지 확인한다. Extraction diagnostics가 남은 completed artifact는 offline artifact로 읽을 수 있지만 causal replay input으로 승격하지 않는다. 또한 `RunMetadata.family_id`와 family-bound approved lineage policy의 `family_id`가 정확히 일치해야 하며, family를 Ground Truth, `run_type` 또는 label로 보충하거나 추론하지 않는다. Family-less legacy policy는 historical reproduction용이므로 causal input으로 승격하지 않는다. Selector provenance가 없는 legacy/manual artifact, selector가 실패한 artifact 또는 하나의 선택 lineage provenance로 해석할 수 없는 artifact도 causal input으로 승격하지 않는다.

Envelope는 별도 model이며 다음 기존 파일을 생성하거나 변경하지 않는다.

- `r1_evidence.jsonl`
- `r1_extraction_summary.json`
- `r1_collection_provenance.json`

따라서 #228 generic S3 2-artifact 계약, 기존 artifact bytes/hash, #259 WMI reference와 collection provenance 계약은 유지된다.

## 5. #232 Temporal Replay 전달 계약

#232 consumer는 기존 Evidence와 같은 `evidence_id`의 availability record를 결합하고 다음 조건에서만 Evidence를 사용할 수 있다.

```text
available_at <= replay_time
```

현재 `available_at`은 causal availability envelope에서 제공되며 #232의 `r1_causal_replay.py`가 `available_at <= replay_time` gate로 소비한다. 상세 activation, event-time window, terminal partial tick과 실행 provenance 계약은 [R1 causal Temporal Replay 계약 v0.1](r1-causal-temporal-replay-v0.1.md)을 따른다. 기존 whole-episode R1 `Evidence.timestamp`만 사용 가능 시각으로 간주해 계산한 TTSD는 causal 조기인지 결과로 해석하지 않는다. Role5의 공식 eligible episode/TTSD 계산 연결은 후속 작업이며, #231은 Role1 weight·threshold·stopping이나 Role5 TTSD 계산 자체를 구현하지 않는다.

동일 `available_at`의 결정적 ordering key는 다음과 같다.

```text
(available_at, timestamp, evidence_id)
```

`timestamp`는 direct Event 의미와 provenance 검증에 계속 사용한다. `available_at` 이전 replay point에 Evidence를 소급 투입하지 않는다. #232는 activation time과 semantic event-time window를 분리하며, 이번 계약은 Role1 weight·threshold·stopping이나 Role5 TTSD 계산을 정의하지 않는다.

## 6. 확장 지점

향후 incremental/window selector가 후속 후보와 late Event를 닫는 versioned 규칙을 제공하면 selector policy와 availability contract를 함께 versioning해 `available_at < run_end`를 허용할 수 있다. 현재 family policy에는 fixed close window가 없으므로 v0.1에서 임의 시간값을 추가하지 않는다.
