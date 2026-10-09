# R1 반복 평가 selector v0.1

> 상태: development implementation / Pair-002 재검증 완료
> 범위: R1-V02의 host-local 3-Event lineage 선택
> 비범위: detector, 공격 분류, production runner, Fusion tuning, final evaluation

## 1. 목적

R1 selector는 NormalizedEvent batch에서 Evidence 평가 대상으로 사용할 anchor와 terminal을 같은 규칙으로 재현한다. selector 자체는 공격을 판정하지 않으며, 선택 결과를 approved lineage policy와 비교하는 책임은 기존 R1 Evidence extractor에 있다.

```text
NormalizedEvent batch
→ R1 selector
→ R1LineageSelection
→ R1LineageInput
→ run_r1_evidence_pipeline()
→ Evidence
```

수동 `R1LineageInput` API는 Pilot 점검과 명시적 재현을 위해 그대로 유지한다.

## 2. Selector policy

`R1SelectorPolicy`는 평가 전에 동결하는 immutable 입력이다.

| 필드 | 의미 |
| --- | --- |
| `policy_id` | selector policy 식별자 |
| `version` | selector semantic version |
| `config_hash` | 동결한 policy payload의 재현용 hash |
| `lineage_event_count` | terminal부터 anchor까지 포함할 `process_create` Event 수 |

R1-V02 development 재검증에는 다음 payload를 사용했다.

```json
{"lineage_event_count":3,"policy_id":"r1-structural-lineage-selector","version":"v0.1"}
```

위 key 정렬 compact JSON의 SHA-256은 `669520854868ae24182f502a2c118e66fce9a0fc464283232990182fa848072d`다. 이 policy는 구조적 선택 범위를 고정할 뿐 production approved lineage policy를 대신하지 않는다.

Approved lineage policy는 “선택된 lineage가 승인 계보와 같은가”를 판단한다. Selector policy는 “어느 lineage를 평가할 것인가”를 정한다. 두 policy의 ID, version, hash와 각 policy의 책임은 서로 독립적이다. Repository-managed approved policy의 config와 loader 계약은 [R1 승인 계보 정책 관리 계약 v0.1](r1-approved-lineage-policy-v0.1.md)에 정의한다. 다만 selector를 Evidence 추출 경로에 연결할 때 `lineage_event_count`는 `approved_lineage` 길이와 같아야 하며, 다르면 Event 선택 전에 입력 오류로 거부한다.

## 3. 입력과 출력

입력은 하나의 `run_id`와 하나의 `host_id` 범위에 속하는 `NormalizedEvent` iterable이다. 호출자는 evaluation Run의 UTC `run_start`를 runtime metadata로 선택적으로 전달할 수 있다. `run_start`는 selector policy payload가 아니므로 기존 policy ID/version/config hash를 변경하지 않는다. Selector는 iterable을 먼저 materialize하며 다음 R1 Event만 후보 관계에 사용한다.

- `source = sysmon`
- `source_layer = raw_telemetry`
- terminal/parent: `event_type = process_create`
- follow-on: `event_type = network_connection`
- `process.process_guid`와 `process.parent_process_guid` 기반 연결
- child와 network Event의 timestamp가 선행 Event보다 빠르지 않음

성공 시 `R1LineageSelection`은 다음 provenance를 반환한다.

- `run_id`
- `entity_id = host_id`
- `anchor_event_id`
- `terminal_event_id`
- `context_event_ids`: `run_start`보다 이르지만 lineage 복원에 사용한 Event ID의 anchor→terminal 방향 순서
- selector policy ID/version/config hash

실패 시 selection은 `None`이며 구조화된 selector diagnostic을 반환한다. 진단은 공격 여부나 Evidence가 아니다.

## 4. 결정적 선택 규칙

1. batch의 Event ID와 run/host 범위를 검증한다.
2. R1 범위의 EID 1/EID 3 역할 Event에 GUID가 모두 존재하는지 확인한다.
3. `run_start`가 있으면 `timestamp >= run_start`인 `process_create`만 terminal 후보가 될 수 있다. `timestamp < run_start`인 Event는 부모 방향 lineage 복원에만 사용할 수 있다.
4. 같은 run/host/GUID로 연결된 모든 network Event의 `network.timestamp >= process.timestamp`일 때만 해당 `process_create`를 terminal 후보로 만든다. Selector candidate 범위에서 하나라도 terminal보다 이른 network Event를 발견하면, 같은 GUID나 다른 GUID에 정상 후보가 함께 있어도 `temporal_inversion`으로 거부한다.
5. terminal 후보가 정확히 하나일 때만 부모 GUID를 따라 `lineage_event_count`만큼 올라간다.
6. policy 경계에서 마지막으로 도달한 Event를 anchor로 선택하고, 선택 lineage 중 `run_start`보다 이른 Event는 `context_event_ids`로 분리한다.

후보와 결과는 JSONL 행 순서, Python set/dict iteration 순서에 의존하지 않는다. Temporal inversion 검사를 후보 수 판단보다 먼저 적용하며, inversion이 없을 때만 terminal 없음, 단일 terminal, 복수 terminal ambiguity를 판단한다. 여러 terminal 후보를 timestamp나 Event ID로 임의 선택하지 않고 ambiguity로 거부한다. 하나의 terminal이 여러 후속 network Event를 가진 경우 selector는 network Event 하나를 선택하지 않는다. 연결된 network Event가 모두 terminal과 같거나 늦고 terminal만 유일하면 기존 pipeline이 모든 follow-on을 독립 Evidence로 처리한다.

## 5. Fail-closed 경계

현재 selector diagnostic은 다음과 같다.

- `empty_event_batch`
- `mixed_run_scope`
- `mixed_host_scope`
- `duplicate_event_id`
- `missing_process_guid`
- `duplicate_process_guid`
- `no_terminal_candidate`
- `ambiguous_terminal_candidate`
- `truncated_lineage`
- `lineage_cycle`
- `temporal_inversion`

GUID 누락, 중복, 끊긴 부모 edge, cycle, 시간 역전 또는 의미적으로 구분할 수 없는 복수 terminal이 있으면 anchor/terminal을 반환하지 않는다. PID는 GUID 대체 키로 사용하지 않는다.

## 6. Label leakage 방지

Selector policy와 구현은 다음 값을 입력 또는 조건으로 사용하지 않는다.

- Ground Truth, `run_type`, Attack/Normal label, 평가 결과
- `cmd.exe`, `cscript.exe` 등 특정 process name
- PID fallback
- Pair별 source RecordId 또는 Event ID
- 내부 destination IP/port

동일 selector policy를 Normal과 Attack에 똑같이 적용한다. Process name은 selector 이후 approved lineage 비교에서만 사용한다.

## 7. Pipeline 연결

`run_r1_evidence_pipeline_with_selector()`는 selector 결과가 있을 때만 기존 `R1LineageInput`을 만들고 `run_r1_evidence_pipeline_with_diagnostics()`를 호출한다. `context_event_ids`는 full lineage 비교에는 사용하지만 `Evidence.event_ids`에서는 제외한다. 선택 실패 시 Evidence를 만들지 않고 selector diagnostic을 결과에 보존한다.

기존 API는 변경하지 않는다.

- `run_r1_evidence_pipeline(..., lineage_inputs=...)`
- `run_r1_evidence_pipeline_with_diagnostics(..., lineage_inputs=...)`

Selector policy provenance와 선택 상태·진단은 `R1SelectorResult`와 artifact summary의 `selector`에 기록한다. Approved policy와 선택된 anchor/terminal은 `lineage_inputs`에 기록하며, pre-Run context를 사용한 경우 같은 항목의 `context_event_ids`에 별도로 보존한다. Context ID가 없는 기존 summary 형식도 loader가 계속 허용한다.

## 8. Pair-002 development 재검증

Google Drive의 동결 원본을 임시 경로에서 읽고 기존 raw SHA-256과 일치한 뒤, 전체 Sysmon JSONL을 NormalizedEvent로 변환했다. source RecordId, process name, endpoint를 selector 입력으로 사용하지 않았다.

| Run | selector | Evidence | 기존 수동 검증과 비교 |
| --- | --- | --- | --- |
| Attack `RUN-20261005-912` | 유일한 3-Event lineage 선택, diagnostics 없음 | lineage deviation 1, network follow-on 1 | 일치 |
| Normal `RUN-20261005-913` | 유일한 3-Event lineage 선택, diagnostics 없음 | lineage deviation 0, network follow-on 1 | 일치 |

입력 Event 순서를 반대로 바꿔도 selection과 Evidence ID가 동일했다. 생성 결과는 임시 artifact writer, loader, provenance resolver까지 통과했다. 원본과 생성 artifact는 저장소에 포함하지 않았다.

## 9. Production 제한

- production runner/CLI에는 연결하지 않는다.
- R1 analysis window 전체 계약은 아직 정하지 않았다. `run_start`는 terminal/Evidence eligibility 하한과 pre-Run lineage context를 구분할 뿐 `available_at`, watermark 또는 causal window를 정의하지 않는다.
- production approved lineage policy를 이번 구현에서 동결하지 않는다.
- Pair-002는 development tuning 전용이며 training, validation, test, holdout 또는 final evaluation 승인이 아니다.
- Fusion weight, window, threshold, stopping과 Role5 final evaluation은 별도 책임이다.
- 반복 dataset을 확대해 구조 후보가 실제로 유일한지 추가 검증해야 한다.
