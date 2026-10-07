# R1 Pair-002 실제 development telemetry Evidence E2E 검증

> 상태: PASS / development validation
> Issue: #184 `[증거 엔지니어링] 실제 R1 Pilot telemetry 기반 Evidence E2E 검증`
> 주의: Issue 제목과 달리 Pair metadata의 정식 분류는 `development`다. 이 기록은 Pilot, holdout, final evaluation 또는 production readiness 승인이 아니다.

## 1. 목적

R1 Evidence 구현이 합성 fixture뿐 아니라 실제 Pair-002 Sysmon telemetry에서도 다음 경로를 설계한 의미대로 통과하는지 재현 검증한다.

```text
Raw Sysmon
→ NormalizedEvent v0.3
→ R1 candidate Evidence
→ Run별 artifact
→ artifact loader
→ Evidence provenance resolver
```

새 탐지 조건, managed vocabulary, Fusion 설정 또는 반복 평가 selector는 이 검증에서 추가하지 않는다. 원본 telemetry와 생성 artifact도 저장소에 포함하지 않는다.

## 2. 검증 범위

- Pair: `R1-PAIR-20261005-002`
- Attack: `RUN-20261005-912`
- Normal: `RUN-20261005-913`
- 입력: Sysmon EID 1과 EID 3 JSONL
- entity 범위: 동일한 단일 host `<target-host>`
- Evidence:
  - `remote_session_process_lineage_deviation`
  - `remote_process_network_follow_on`
- 제외: Fusion scoring, production runner 연결, managed vocabulary 등록, final evaluation, holdout 승인

명시적인 source RecordId는 이 development Pair에서 validation 입력을 찾는 데만 사용했다. extractor에 Ground Truth 또는 `run_type`을 전달하지 않았고, 이 RecordId나 생성된 `event_id`를 production selector로 사용하지 않는다.

## 3. 검증 환경 및 기준 commit

| 항목 | 값 |
| --- | --- |
| 검증일 | 2026-10-06 |
| 기준 branch | `docs/evidence-engineering/r1-pair002-e2e-validation` |
| 검증 commit | `72fd40a53f81a03b4312c5a4701a9ad1cd591ab6` |
| `origin/develop` | `72fd40a53f81a03b4312c5a4701a9ad1cd591ab6` |
| Python | 3.13.15 |
| NormalizedEvent schema | v0.3 |
| R1 extractor | `r1-v0.1` |
| Event vocabulary | `configs/event_types_v0.2.yaml` |
| Evidence managed vocabulary | `configs/evidence_types_v0.2.yaml` |

검증 시작 시 HEAD와 최신 `origin/develop`이 일치했고 작업 트리는 clean이었다. 연결된 Google Drive 플러그인으로 동결된 Pair 폴더의 `README.md`, `index.json`, `SHA256SUMS.txt`, manifest와 `distribution/jsonl-original`의 두 JSONL을 직접 읽었다. 원본과 생성 artifact는 임시 경로에서만 사용하고 검증 후 삭제했다.

## 4. 입력 Pair metadata

| 항목 | 실제 값 |
| --- | --- |
| Pair | `R1-PAIR-20261005-002` |
| family / variation / repetition | `remote_management` / `V02` / `2` |
| Attack / Normal | `RUN-20261005-912` / `RUN-20261005-913` |
| dataset tier | `development` |
| collection | `complete` |
| `py313_validation_status` | `pending` |
| `source_review_status` | `local_unpushed_commit` |
| `eligible_for_holdout` | `false` |
| `used_for_pilot` | `false` |
| Role5 final evaluation approval | 수집 시점에 부여되지 않음 |

이번 Python 3.13 Evidence E2E 성공은 Pair metadata의 공식 `py313_validation_status`를 변경하지 않는다. 해당 상태는 수집 validator와 dataset 승인 절차의 책임이다.

원본 Pair metadata의 `dataset_tier = development`와 별도로, Role5의 현재 사용 분류는 [PR #205](https://github.com/train3-test2/incident-awareness-engine/pull/205)에 기록된 `development tuning 전용`이다. training, validation, test, holdout 및 final evaluation 입력에서는 제외한다.

## 5. Raw telemetry SHA-256

| Run | 파일 | Bytes | SHA-256 | Pair 기록과 일치 |
| --- | --- | ---: | --- | --- |
| Attack | `RUN-20261005-912_sysmon-0001.jsonl` | 105,669 | `dddf1d7cb78d4958a7b84fecc8e9ff14de56a63bd631758e6e7638ed6f3a9197` | PASS |
| Normal | `RUN-20261005-913_sysmon-0001.jsonl` | 136,309 | `f3b9157f2a4ec56710a555194a701b9b43dea52de1883319c4b94e89616bf95d` | PASS |

두 값은 Pair의 `SHA256SUMS.txt`와 각 Run manifest의 `RAW-002` JSONL 항목에 모두 일치했다. 해시 일치 후에만 이후 단계를 실행했다.

## 6. Sysmon EID 1 / EID 3 현황

| Run | 전체 행 | EID 1 / `process_create` | EID 3 / `network_connection` | 정규화 결과 |
| --- | ---: | ---: | ---: | --- |
| Attack | 98 | 74 | 24 | 98 |
| Normal | 97 | 73 | 24 | 97 |

지원 범위 밖 Event ID, 빈 JSONL 행 또는 JSON object가 아닌 행은 없었다.

## 7. NormalizedEvent 검증

전체 Event에서 다음 계약을 확인했다.

- `run_id` 보존
- `host_id = <target-host>`
- `source = sysmon`, `source_layer = raw_telemetry`
- EID 1은 `process_create`, EID 3은 `network_connection`
- `source_event_id`는 원본 Sysmon RecordId 문자열
- `raw_ref.raw_log_id = RAW-002`, `segment_no = 1`, 물리적 JSONL 행 번호와 source RecordId 보존
- EID 1의 `ProcessGuid`와 `ParentProcessGuid` 문자열 보존
- EID 3의 `ProcessGuid` 보존 및 계약에 따라 `parent_process_guid = None`
- `timestamp_source = event_time`
- `timestamp`는 `EventData.UtcTime`에서 정규화된 UTC millisecond 값
- PID는 계보 또는 EID 1→EID 3 연결 키로 사용하지 않음

핵심 RecordId는 `source_event_id`와 `raw_ref.source_record_id`를 함께 사용해 각각 유일한 Event로 resolve했다.

| Run | 역할 | RecordId / raw 행 | 생성된 validation event_id | timestamp |
| --- | --- | --- | --- | --- |
| Attack | anchor | `1275` / 7 | `evt-2364b7e5-3405-5d25-953e-7f2b06842f1a` | `2026-10-05T19:33:26.037Z` |
| Attack | intermediate | `1325` / 57 | `evt-50cef4c6-4ca5-5c24-9ace-60ecc456a26f` | `2026-10-05T19:38:25.994Z` |
| Attack | terminal | `1327` / 59 | `evt-4b8e3692-bf1e-5609-8cd3-cc29c72c39ec` | `2026-10-05T19:38:26.253Z` |
| Attack | network | `1350` / 82 | `evt-39810dd2-1568-5565-86de-d3f73b64259f` | `2026-10-05T19:41:26.617Z` |
| Normal | anchor | `1290` / 4 | `evt-dea41dfd-d919-5f6d-823b-ff61015ce931` | `2026-10-05T19:56:52.508Z` |
| Normal | intermediate | `1335` / 49 | `evt-228f3eab-23e9-5e54-8bea-1e112dd5c19b` | `2026-10-05T20:01:53.490Z` |
| Normal | terminal | `1337` / 51 | `evt-1b935756-473d-5f8e-ae8f-c59741a1521f` | `2026-10-05T20:01:53.555Z` |
| Normal | network | `1373` / 87 | `evt-38dbda1a-eb32-5035-b7ba-cfa3c3950372` | `2026-10-05T20:04:52.808Z` |

위 `event_id`는 `run_id`, `RAW-002`, segment, 물리적 행 번호와 RecordId로 이번 validation에서 결정적으로 생성된 결과다. 특정 Event ID를 반복 평가 config에 고정하는 selector contract가 아니다.

## 8. 실제 Attack / Normal lineage

| Run | 관측 lineage | GUID edge | network edge | 시간 순서 |
| --- | --- | --- | --- | --- |
| Attack | `wsmprovhost.exe → cscript.exe → powershell.exe` | 각 child `ParentProcessGuid`가 직전 parent `ProcessGuid`와 일치 | RecordId 1350 EID 3 GUID가 terminal GUID와 일치 | PASS |
| Normal | `wsmprovhost.exe → cmd.exe → powershell.exe` | 각 child `ParentProcessGuid`가 직전 parent `ProcessGuid`와 일치 | RecordId 1373 EID 3 GUID가 terminal GUID와 일치 | PASS |

두 network Event는 동일한 내부 목적지 endpoint 특성을 공유한다. 실제 host와 내부 목적지 IP/port는 저장소 문서에 기록하지 않고 외부 원본 Pair artifact에만 보존한다. 모든 edge는 동일 `run_id`와 `host_id` 범위에서 GUID로 연결했으며 PID fallback은 사용하지 않았다. 프로세스 이름은 결과 설명과 동결 policy의 sequence 비교에만 사용했고, 특정 이름 자체를 Attack label로 해석하지 않았다.

## 9. Validation용 approved lineage policy

저장소에는 공식적으로 동결된 production approved lineage policy config가 없다. 이번 검증에는 기존 R1-V02 정상 계보 의미를 표현하는 다음 임시 policy를 사용했다.

| 항목 | 값 |
| --- | --- |
| `policy_id` | `r1-v02-development-connection` |
| `version` | `v0.1` |
| `config_hash` | `59b5eb5a5637f4527a4725a310aa1bece6a9da8bd7f1257edee03be1b15f0b78` |
| approved lineage | `wsmprovhost.exe → cmd.exe → powershell.exe` |
| purpose | `temporary_development_validation_only` |

hash는 `policy_id`, `version`, `approved_lineage`를 key 정렬한 compact JSON의 SHA-256이다. 이 policy는 Pair의 Attack/Normal label이나 Ground Truth를 관찰해 생성하지 않았으며, production policy freeze 또는 평가 승인을 의미하지 않는다.

## 10. Evidence 생성 결과

`run_r1_evidence_pipeline()`과 diagnostics companion API가 같은 Evidence 결과를 반환하는지 함께 확인했다.

### Attack

| Evidence type | evidence_id | semantic provenance | timestamp |
| --- | --- | --- | --- |
| `remote_session_process_lineage_deviation` | `E-71225400-91e7-598d-8b62-69600484a820` | RecordId `1275 → 1325 → 1327` | `2026-10-05T19:38:26.253Z` |
| `remote_process_network_follow_on` | `E-198f0a21-dbe6-5a26-9079-dd35dc516613` | RecordId `1327 → 1350` | `2026-10-05T19:41:26.617Z` |

### Normal

| Evidence type | evidence_id | semantic provenance | timestamp |
| --- | --- | --- | --- |
| `remote_process_network_follow_on` | `E-da1fa18e-8320-5f36-8ac5-97488b4e6eae` | RecordId `1337 → 1373` | `2026-10-05T20:04:52.808Z` |

모든 Evidence에서 다음을 확인했다.

- `entity_id = <target-host>`
- `feature_channel_group = fusion_feature`
- `extractor_version = r1-v0.1`
- `event_ids`는 실제 correlation에 사용한 `NormalizedEvent.event_id`이며 위 RecordId 의미 순서를 유지
- `timestamp`는 linked Event 중 가장 늦은 `NormalizedEvent.timestamp`
- `raw_ref`와 `source_event_id`는 Evidence에 복제하지 않음

Normal과 Attack 양쪽에서 network follow-on이 발생했다. 따라서 `feature_channel_group = fusion_feature`가 단독 positive attack indicator를 뜻하지 않는다.

## 11. Diagnostics 결과

| Run | diagnostics | 해석 |
| --- | --- | --- |
| Attack | `[]` | 추가 fail-closed diagnostic 없음 |
| Normal | `[]` | 추가 fail-closed diagnostic 없음 |

실제 선택 계보에서 missing GUID, truncated lineage, cycle, duplicate GUID ambiguity, invalid parent edge, process name 누락 또는 temporal violation은 발생하지 않았다. `diagnostics = []`는 해당 extraction diagnostic이 없었다는 뜻일 뿐 공격 부재, telemetry completeness, dataset 승인 또는 평가 완료를 의미하지 않는다.

## 12. Artifact 생성 결과

임시 Run별 출력 디렉터리에서 `run_and_write_r1_evidence_artifacts()`를 실행했다.

| Run | status | count | Evidence JSONL SHA-256 | summary SHA-256 |
| --- | --- | ---: | --- | --- |
| Attack | `completed` | 2 | `48daef65704b5c0b513550cc4a2fe766f1a418869f66383b5e54e89c08e4ffce` | `545d4c6f08c9d2c092a26709ab58f6ea3d15fa49632bb71f98e26d074a0e6671` |
| Normal | `completed` | 1 | `b0fa9a2d2789da1f3dd0257789a4d143988c035eb225aef136be8e5b5455e8b4` | `1b882055456c96cf16f26c3163d0d38de9504733d108a951144ef5ce5c15958a` |

위 값은 이번 deterministic Evidence artifact의 해시이며 Raw telemetry 해시가 아니다. summary의 `run_id`, `extractor_version`, count, diagnostics와 Evidence SHA가 실제 파일에 일치했고, lineage input의 anchor/terminal 및 policy ID/version/hash가 보존됐다. Evidence ID는 Run별 artifact 안에서 유일했고 writer canonical ordering을 따랐다.

## 13. Loader 검증 결과

`load_r1_evidence_artifacts()`와 `load_r1_extraction_summary()`를 실제 생성 artifact에 각각 적용했다. 두 public API가 반환한 summary는 writer 결과와 동일했다.

| 검증 항목 | Attack | Normal |
| --- | --- | --- |
| completed status / 파일 존재 | PASS | PASS |
| Evidence SHA-256 | PASS | PASS |
| `evidence_count` | PASS | PASS |
| `run_id` / `extractor_version` | PASS | PASS |
| canonical Evidence ordering | PASS | PASS |
| `evidence_id` uniqueness | PASS | PASS |
| candidate type 허용 범위 | PASS | PASS |
| lineage/policy provenance structure와 ordering | PASS | PASS |
| summary ↔ Evidence cross-validation | PASS | PASS |

failed artifact를 정상 Evidence로 소비하지 않는 경계는 기존 artifact 회귀 테스트에서 유지됨을 함께 확인했다. Loader가 허용한 R1 candidate type은 extractor-version별 artifact 계약이며 managed vocabulary 등록을 의미하지 않는다.

## 14. Provenance 검증 결과

`resolve_r1_evidence_provenance()`를 loader가 반환한 Evidence와 해당 Run의 전체 NormalizedEvent batch에 적용했다.

- Event batch의 `event_id` 유일성: PASS
- 모든 `Evidence.event_ids` 존재: PASS
- Evidence와 linked Event의 `run_id` 일치: PASS
- `Evidence.entity_id == NormalizedEvent.host_id`: PASS
- `Evidence.event_ids` semantic ordering 보존: PASS
- `Evidence.timestamp == max(linked Event.timestamp)`: PASS
- resolve된 Event의 `raw_ref`와 `source_event_id` 추적: PASS

확인된 provenance chain은 다음과 같다.

```text
Evidence.event_ids
→ NormalizedEvent.event_id
→ NormalizedEvent.raw_ref
→ RAW-002 / source RecordId / 물리적 JSONL 행
→ Pair Run context
```

Evidence에 raw provenance를 중복 저장하지 않아도 원본까지 연결됐다.

## 15. Normal / Attack 비교

| 항목 | Attack | Normal |
| --- | --- | --- |
| 실제 중간 프로세스 | `cscript.exe` | `cmd.exe` |
| approved lineage와 비교 | 다름 | 같음 |
| lineage deviation | 1 | 0 |
| network follow-on | 1 | 1 |
| 총 Evidence | 2 | 1 |
| diagnostics | `[]` | `[]` |

이 결과는 동결된 계보와 다른 complete lineage가 lineage deviation을 생성하고, 공통 후속 연결은 두 Run 모두에서 생성되는 현재 candidate 의미와 일치한다. 특정 중간 프로세스 이름 자체가 공격 판정 조건인 것은 아니다.

Normal의 lineage deviation 0건은 수동으로 선택한 단일 Normal lineage가 approved lineage와 일치했다는 의미다. Run 안의 다른 후보 lineage는 평가하지 않았으므로 Normal Run 전체의 false positive가 0건이라는 뜻이 아니며, 이 한 Pair로 false-positive rate를 추정할 수 없다. 반복 평가용 deterministic selector를 도입해 전체 후보 lineage를 평가한 뒤에야 해당 특성을 판단할 수 있다.

## 16. 반복 평가 selector 요구사항

이번 검증은 특정 development Pair의 source RecordId를 사용해 anchor와 terminal을 명시적으로 resolve했다. 이는 수동 validation에는 적합하지만 production 또는 반복 평가 selector가 아니다.

후속 selector는 다음 조건을 만족해야 한다.

- Ground Truth, `run_type`, Attack/Normal label에 의존하지 않음
- `cmd.exe`, `cscript.exe` 등 프로세스 이름으로 label을 역추론하지 않음
- 동일 NormalizedEvent 입력에 결정적 결과를 생성
- NormalizedEvent 계약만으로 모든 Run에 같은 규칙을 적용
- selector policy/version provenance를 재현 가능하게 기록
- Event ID를 frozen config에 직접 고정하지 않음

구체적인 selector는 별도 Issue/PR에서 설계하고 구현한다.

## 17. R1 analysis window 관찰 결과

| Run | anchor Event → terminal Event | terminal Event → network Evidence |
| --- | ---: | ---: |
| Attack | 300.216초 | 180.364초 |
| Normal | 301.047초 | 179.253초 |

첫 번째 간격은 명시적으로 선택한 anchor Event부터 terminal Event까지의 시간이다. Attack에서는 terminal Event 시점이 lineage deviation Evidence timestamp와 같지만, Normal에서는 lineage deviation Evidence가 생성되지 않았다. 두 번째 간격은 terminal Event부터 EID 1→EID 3 관계가 완성된 network follow-on Evidence까지의 시간이다. 이 측정은 미래 Event를 먼저 사용하지 않는 no-look-ahead 원칙을 유지한다.

위 간격은 Pair-002의 관찰값일 뿐 production Fusion window 권고값이 아니다. analysis window, cadence, score weight, threshold와 stopping policy는 Role1 tuning 책임으로 남긴다.

## 18. Managed vocabulary gate 판단

`configs/evidence_types_v0.2.yaml`에는 현재 다음 R1 type이 없다.

- `remote_session_process_lineage_deviation`
- `remote_process_network_follow_on`

이번 검증으로 다음 기술적 gate를 충족했다.

1. 실제 development telemetry에서 두 candidate Evidence의 생성 확인
2. artifact writer, loader와 provenance resolver까지 전체 E2E 확인
3. 실제 telemetry 검증 전 candidate로 유지한다는 조건 충족

따라서 managed vocabulary 등록은 후속 독립 Issue/PR로 진행할 수 있다. 등록은 scoring weight, production readiness, production approved policy, holdout 또는 final evaluation 승인을 의미하지 않는다. 특히 network follow-on은 Normal과 Attack 양쪽에서 발생하므로 단독 공격 신호로 등록하거나 해석하지 않는다.

## 19. Role1 / Role5 소비 시 주의사항

### Role1

실제 Evidence 생성과 artifact 경계가 확인되어 vocabulary 등록 후 development tuning 입력으로 연결할 기술적 기반은 마련됐다. 다음 항목은 Role1 결정 사항이다.

- scoring profile 포함 여부와 weight
- Fusion window와 cadence
- threshold
- persistence와 stopping

network follow-on에 단독 positive weight가 있다고 전제하지 않는다.

### Role5

Run별 artifact 생성, loader와 provenance 경로는 확인됐다. 그러나 Pair-002의 Role5 사용 분류는 [PR #205](https://github.com/train3-test2/incident-awareness-engine/pull/205)에 기록된 `development tuning 전용`이며 training, validation, test, holdout 또는 final evaluation용 데이터가 아니다. `py313_validation_status`, source review, split/holdout과 final evaluation 승인은 Evidence E2E 성공과 별도의 dataset gate다.

현재 제외 기록은 declarative provenance이며 자동 enforcement가 아니다. [Issue #208](https://github.com/train3-test2/incident-awareness-engine/issues/208)은 dataset/split 구성 경계가 usage/exclusion sidecar를 필수로 소비하고 제외 Run 입력을 오류로 거부하도록 연결하는 후속 작업이다. #208이 완료되기 전에는 이 기록만으로 코드가 Pair-002를 자동 차단한다고 해석하지 않는다.

## 20. Dataset 상태 및 제한사항

- 원본 Pair metadata의 `dataset_tier`는 `development`다.
- Role5의 현재 실제 사용 분류는 `development tuning 전용`이다.
- training, validation, test, holdout 및 final evaluation 입력에서 정책·기록상 제외한다.
- 위 제외는 현재 declarative provenance이며 자동 enforcement는 Issue #208의 후속 범위다.
- 공식 Python 3.13 collection validator 상태는 metadata상 `pending`이다.
- 수집 코드의 source review 상태는 `local_unpushed_commit`이다.
- 공식 development 수량과 Pilot 사용 대상이 아니다.
- Role5 final evaluation 승인을 받지 않았다.
- telemetry completeness는 Evidence summary에 제공되지 않아 `not_provided`다.
- 이 결과로 recall, false-positive rate, TTSD 분포 또는 일반적인 모델 성능을 주장하지 않는다.
- validation용 policy와 명시적 Event 선택을 production 계약으로 승격하지 않는다.

## 21. 후속 작업

- 두 R1 candidate의 managed Evidence vocabulary 등록
- Ground Truth와 label에 독립적인 반복 평가 selector 설계·구현
- production approved lineage policy와 config lifecycle 동결
- production runner/CLI에서 R1 batch API 호출 경로 연결
- Role1 R1 Fusion profile, window, weight, threshold와 stopping 결정
- Issue #208의 usage/exclusion sidecar 기반 train/validation/test 자동 제외 강제
- dataset source review 및 공식 Python 3.13 validation
- holdout/final evaluation 승인 절차

## 22. 결론

최신 `origin/develop`의 현재 코드로 Pair-002 실제 development telemetry를 처리한 결과, 예상한 NormalizedEvent, lineage correlation, 두 R1 candidate Evidence, immutable artifact, loader와 provenance resolver 계약이 모두 통과했다. 코드 결함이나 예상과 다른 detector 동작은 발견되지 않았다.

따라서 Pair-002 development telemetry를 이용한 Evidence E2E 검증과 후속 요구사항 도출은 완료된 것으로 판단한다.

다만 Issue #184에 포함된 Role1 Fusion 입력용 Evidence 전달과 Role5 평가 입력용 artifact 전달은 별도로 완료 여부를 확인해야 한다. 이 validation record만으로 Issue #184 전체가 완료됐다고 판단하거나 close하지 않는다.

managed vocabulary, 반복 평가 selector, production policy/runner, Fusion tuning과 dataset 승인은 별도 후속 작업으로 분리한다.
