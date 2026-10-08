# R1 다중 Run development Evidence 검증

> 상태: PASS / Issue #227 development regression 범위
> 검증일: 2026-10-09
> availability: `OFFLINE WHOLE-EPISODE ONLY`

## 1. 목적과 범위

동일한 selector와 approved lineage policy를 Pair별 조정 없이 다음 두 Pair에 적용해 R1 Evidence 경로의 반복 가능성을 검증한다.

- Pair-002: 이전 Run-level tier 계약으로 수집한 legacy development/tuning baseline
- Pair-003: 현재 Pair-owned tier 계약으로 수집한 development Pair

검증 경로는 다음과 같다.

```text
Raw Sysmon EID 1/EID 3
→ NormalizedEvent v0.3
→ deterministic selector
→ repository-managed approved lineage policy
→ R1 Evidence pipeline
→ artifact writer
→ artifact loader
→ provenance resolver
```

Ground Truth, `run_type`, Attack/Normal label, Pair별 RecordId나 Event ID, process name, PID와 endpoint는 selector 또는 policy 선택 입력으로 사용하지 않았다. Pair 분류와 기존 기대값은 extraction이 끝난 뒤 결과 비교에만 사용했다.

## 2. 실행 기준

| 항목 | 값 |
| --- | --- |
| 작업 branch | `feature/evidence-engineering/r1-multi-run-regression` |
| Evidence execution commit | `fb8aab55c7f70dd5adb7230f84b8d349bf9a9fac` |
| Pair-003 collection source commit | `816c3c2f80b2e664206ed277a9abc5d33ddec9dd` |
| Pair-003 runner bundle SHA-256 | `c9b575af86c78e163a5db7aca67e8d1e11e057bd10ba2e61a888c63336af132f` |
| Pair-003 rendered scenario SHA-256 | `8b0964c613868611914a1bc032d66a7ba6e9e08ef540b6c8dc80ac7a155f3a9c` |
| NormalizedEvent schema | v0.3 |
| R1 extractor | `r1-v0.1` |

검증 시작 시 `origin/develop`은 collection source commit `816c3c2`였고 작업 branch HEAD보다 한 merge commit 앞섰다. 해당 차이는 S3 lifecycle 문서·infra·테스트뿐이며 Evidence, selector, approved policy, normalization 또는 artifact 코드에는 차이가 없다. branch를 merge, rebase 또는 switch하지 않고 실제 HEAD를 Evidence execution commit으로 기록했다.

## 3. Pair-003 자격과 원본 무결성

Pair-003의 렌더링된 scenario와 두 operator trace는 다음 값을 동일하게 기록한다.

| 필드 | 값 |
| --- | --- |
| Pair | `R1-PAIR-20261008-003` |
| `scenario_id` | `R1` |
| `family_id` | `remote_management` |
| `variation_id` | `V02` |
| `repetition` | `3` |
| `dataset_tier` | `development` |
| Normal | `RUN-20261008-915` |
| Attack | `RUN-20261008-916` |

`dataset_tier`의 source of truth는 렌더링된 `scenario.json` 최상위 Pair 값이다. Validator에는 `--dataset-tier` 입력이 없으며, scenario의 `dataset_tier`와 operator trace의 `dataset_tier`가 정확히 같은지 검증한다. 현재 repository validator로 두 Run의 contract 파일, operator trace, manifest, planned lineage를 검증해 모두 PASS했다. Pair-003는 이 current Pair-owned tier contract를 만족하는 development 입력이며 holdout이나 final evaluation 입력이 아니다.

각 Run은 다음 `cmd.exe` 형식으로 검증했다.

```bat
uv run python tools/validate_r1_run.py ^
  --artifact-root <data-root> ^
  --run-id <run-id> ^
  --scenario <scenario.json> ^
  --record-out <record-path>
```

원본 ZIP은 read-only로 취급하고 저장소 밖 validation 경로에만 압축 해제했다.

| 검증 | 결과 |
| --- | --- |
| Pair ZIP SHA-256 | `d1cfc59cf084dbe1a40caa7502169f23408d3799598efe80087e6b08bac6d542` / 일치 |
| `SHA256SUMS.txt` | 40개 파일 재계산 / 불일치 0건 |
| Run별 manifest | EVTX와 JSONL 2개 항목 모두 일치 |
| scenario bytes | 두 Run 모두 `8b0964c613868611914a1bc032d66a7ba6e9e08ef540b6c8dc80ac7a155f3a9c` |

실제 host와 내부 목적지 IP/port는 저장소 문서에 기록하지 않고 외부 원본 Pair와 validation artifact에만 보존한다. 두 Run은 동일 `<target-host>`와 동일 `<internal-endpoint>` 특성을 사용했다.

## 4. 동결 입력 정책

모든 Run에 다음 값을 동일하게 사용했다.

### Selector

- ID: `r1-structural-lineage-selector`
- version: `v0.1`
- config hash: `669520854868ae24182f502a2c118e66fce9a0fc464283232990182fa848072d`
- `lineage_event_count`: `3`

### Approved lineage policy

- ID: `r1-v02-development-connection`
- version: `v0.1`
- config hash: `59b5eb5a5637f4527a4725a310aa1bece6a9da8bd7f1257edee03be1b15f0b78`
- sequence: `wsmprovhost.exe → cmd.exe → powershell.exe`

Approved policy는 저장소 loader로 읽어 hash와 sequence를 재현했다. Pair ZIP에 기록된 값을 실행 source of truth로 사용하지 않았다. 현재 policy는 development validation policy이며 production 또는 final evaluation 승인 정책이 아니다.

## 5. Pair-003 정규화

기존 Sysmon EID 1/EID 3 reader와 normalizer를 사용했다. `raw_log_id=RAW-002`, `segment_no=1`을 사용하고 Event는 `(timestamp, event_id)` 순서로 직렬화해 SHA-256을 계산했다.

| Run | raw SHA-256 | raw/normalized 수 | EID 1 | EID 3 | normalized SHA-256 |
| --- | --- | ---: | ---: | ---: | --- |
| Normal `RUN-20261008-915` | `0bef21fa27eed76a647d2f3a74b684d8a6cba892f5fb8c8ed2f05786c4575827` | 469 / 469 | 443 | 26 | `fcd30d8a276170db45a9322f9ad365ac7981b80f69a1b91f81552c6a5f9fe9fe` |
| Attack `RUN-20261008-916` | `604ae7e4b35ff9151da943ff6554bd796be4b29b577820cb1afdd7b1b43c9e2a` | 211 / 211 | 187 | 24 | `e716dca860279bfedd4841380295866eb5576b325e0b37498c4780b43ed148d8` |

모든 Event에서 `run_id`, `source_event_id`, `raw_ref.raw_log_id`, physical `record_no`, ProcessGuid와 ParentProcessGuid를 기존 계약대로 보존했다.

## 6. Selector 결과

| Run | status | diagnostics | anchor → intermediate → terminal source RecordId |
| --- | --- | --- | --- |
| Normal `RUN-20261008-915` | `selected` | `[]` | `1310 → 1351 → 1353` |
| Attack `RUN-20261008-916` | `selected` | `[]` | `1318 → 1366 → 1368` |

선택된 lineage Event ID는 다음과 같다.

### Normal

- anchor: `evt-1b38ad4c-ec84-544d-b4b8-4f934346ee8b`
- intermediate: `evt-fc3a612e-b802-53ea-aa66-737ce7a16832`
- terminal: `evt-3ab56089-436a-5b7c-ab21-ca2d731561a8`

### Attack

- anchor: `evt-cc7e6565-4272-51d0-bf54-a49ad9ad74ae`
- intermediate: `evt-94d9270b-9a94-51f0-a364-4a2ee65616bd`
- terminal: `evt-c66c8694-e157-5ac8-bbf1-cc63851b820d`

RecordId는 선택 결과를 raw telemetry로 역추적한 사후 provenance이며 selector 입력이나 filter가 아니다.

## 7. Pair-003 Evidence 결과

| Run | Evidence | evidence ID | timestamp |
| --- | --- | --- | --- |
| Normal | `remote_process_network_follow_on` | `E-78622943-2680-5c26-9945-0f6ed967fa5b` | `2026-10-08T14:27:30.935Z` |
| Attack | `remote_session_process_lineage_deviation` | `E-94d39a78-eb8f-520f-a84d-a07cc45736a3` | `2026-10-08T13:52:34.482Z` |
| Attack | `remote_process_network_follow_on` | `E-dd2e13d2-1597-5e48-9aab-da0f90523535` | `2026-10-08T13:55:35.842Z` |

두 Run의 selector diagnostics와 extraction diagnostics는 모두 `[]`다. Normal의 observed lineage는 approved policy와 같아 lineage deviation을 만들지 않았고, Attack의 observed lineage는 동결 policy와 달라 lineage deviation을 만들었다. 두 Run 모두 terminal ProcessGuid와 연결된 network follow-on을 한 건 생성했다.

## 8. Artifact와 provenance

Artifact는 저장소 밖 `<external-validation-root>/<execution-commit>/R1-PAIR-20261008-003/<run-id>/`에 생성했다.

| Run | `r1_evidence.jsonl` SHA-256 | `r1_extraction_summary.json` SHA-256 | loader | provenance resolver |
| --- | --- | --- | --- | --- |
| Normal | `c2e937cf5d8f58a7ea5cdb476a53037c50b5c6b860492e42e444f2ab7022f27f` | `05f31b1621b6e4af6fefba9b36145c96c5e6ffae51a64bbfd50cd0d0f5e89f9d` | PASS | PASS |
| Attack | `3aeec26df6b3739869711e156987815f9fce8260a7f853c0de8d00c27577782b` | `d0ae578bc7a994ab39a1877fdca3b95eef117f4b5e0e332075c76412f3782e9d` | PASS | PASS |

각 Evidence에 대해 다음 역추적을 검증했다.

```text
Evidence.event_ids
→ NormalizedEvent.event_id
→ source_event_id / raw_ref.record_no
→ RAW-002 manifest item
→ 원본 JSONL physical record
```

`Evidence.timestamp`는 참조 Event 중 가장 늦은 `NormalizedEvent.timestamp`와 일치했고, `event_ids` 의미 순서는 lineage의 anchor→terminal 또는 EID 1→EID 3 순서를 유지했다.

## 9. 결정성

각 Pair-003 Run을 다음 세 입력 순서로 독립 실행했다.

1. 원본 JSONL 순서
2. 역순
3. seed `227` 고정 shuffle

두 Run 모두 다음 값이 세 실행에서 동일했다.

- selector selection과 diagnostics
- Evidence ID, type, `event_ids`, timestamp와 features
- `r1_evidence.jsonl` bytes/SHA-256
- `r1_extraction_summary.json` bytes/SHA-256
- provenance resolver 결과

### Fail-closed 검증 경계

기존 synthetic selector regression을 이번 branch에서 다시 실행해 duplicate ProcessGuid, truncated lineage, ambiguous terminal candidate와 temporal inversion이 selection 없이 구조화된 diagnostic으로 fail-closed되는 계약을 재확인했다. Pair-003 실제 raw telemetry를 duplicate, truncated, ambiguous 또는 temporal inversion 형태로 변조하는 신규 actual-run 검증은 수행하지 않았다.

## 10. Pair-002 baseline replay

Pair-002는 current-contract development 수량에 포함하지 않고 legacy development/tuning baseline으로만 사용했다. 로컬에 보존된 frozen raw JSONL을 동일 Evidence execution commit과 동일 selector/policy로 재실행했다.

| Run | selector | Evidence | 현재 evidence SHA-256 | 기존 `9ee868` bytes 비교 |
| --- | --- | --- | --- | --- |
| Attack `RUN-20261005-912` | selected / diagnostics `[]` | lineage deviation 1, network follow-on 1 | `48daef65704b5c0b513550cc4a2fe766f1a418869f66383b5e54e89c08e4ffce` | 동일 |
| Normal `RUN-20261005-913` | selected / diagnostics `[]` | network follow-on 1 | `b0fa9a2d2789da1f3dd0257789a4d143988c035eb225aef136be8e5b5455e8b4` | 동일 |

현재 high-level API가 selector provenance를 summary에 추가하므로 이전 수동 artifact writer의 summary hash와는 다르다. Evidence bytes와 IDs는 이전 검증 결과와 동일하고 현재 loader/provenance resolver도 PASS했다.

## 11. Multi-run 분석과 policy 안정성

Pair-002와 Pair-003에서 다음 결과가 반복됐다.

- 같은 selector policy가 Pair별 RecordId, process name 또는 endpoint 조건 없이 유일한 3-Event lineage를 선택했다.
- 같은 approved policy가 Normal lineage를 승인 계보로, Attack lineage를 deviation으로 비교했다.
- Normal과 Attack 모두 network follow-on을 생성했다. 따라서 network follow-on은 단독 공격 신호가 아니다.
- 모든 Run에서 selector/extraction diagnostics가 비어 있었다.
- 입력 순서를 바꿔도 Pair-003 selector, Evidence, artifact와 provenance가 동일했다.

이는 동일-family development 반복에서 selector/policy 안정성 근거를 강화한다. 다만 current Pair-owned tier 계약으로 수집한 Pair는 Pair-003 한 개뿐이고 Pair-002는 legacy baseline이다. 현재 v0.1 policy에는 explicit family binding과 lifecycle 승격 계약도 없다. 따라서 development frozen candidate 근거는 강화됐지만 production/final evaluation policy로 승격하거나 여러 family에 일반화하지 않는다. 추가 current-contract development Pair 검증과 #234 family binding/lifecycle 결정이 필요하다.

## 12. Role1·Role5 사용 범위

### Role1

- Pair-003의 completed artifact는 offline whole-episode connection check, static Evidence feature 분석 후보와 artifact/interface 연결 확인에만 사용할 수 있다.
- selector와 approved policy identity, diagnostics, Evidence type/count와 artifact hash를 함께 전달해야 한다.
- Fusion score, weight, window, threshold tuning, 모델 선택과 causal temporal evaluation은 아직 승인된 사용 범위가 아니다. Role1의 별도 승인과 #231 `available_at`/watermark 계약 이후에 판단한다.
- Pair-002는 legacy 비교 baseline으로만 사용하고 current-contract development 수량에는 포함하지 않는다.

### Role5

- Pair-003는 current-contract `development` Pair다.
- 실제 train/validation/test split 배정은 Role5 split manifest와 dataset 승인 절차를 별도로 거쳐야 한다.
- Pair-002는 training, validation, test, holdout과 final evaluation에서 제외한다.
- Pair-003도 holdout 또는 final evaluation 결과로 사용하지 않는다.

## 13. Availability 제한

모든 artifact의 availability는 계속 `OFFLINE WHOLE-EPISODE ONLY`다.

- `Evidence.timestamp`는 causal `available_at`이 아니다.
- Temporal Replay와 TTSD를 계산하지 않는다.
- online detection이나 탐지 시간 개선을 주장하지 않는다.
- Production runner/CLI 연결은 #228 범위다.
- `available_at`/watermark는 #231, Temporal Replay/TTSD는 #232 범위다.

## 14. Issue #227 판단

| 항목 | 상태 |
| --- | --- |
| 추가 current-contract development Pair 확보 | 완료: Pair-003 |
| ZIP/manifest/raw integrity | 완료 |
| 동일 selector 적용 | 완료 |
| 동일 approved policy 적용 | 완료 |
| label/RecordId 비의존 실행 | 완료 |
| Run별 selector와 Evidence 결과 | 완료 |
| artifact writer/loader | 완료 |
| provenance resolver | 완료 |
| original/reverse/shuffle 결정성 | 완료 |
| duplicate ProcessGuid/truncated/ambiguous/temporal inversion fail-closed | 기존 synthetic selector regression 재확인 완료. Pair-003 실제 telemetry 변조 검증은 미수행 |
| Pair-002 baseline replay | 완료 |
| pair-specific overfitting 검토 | 완료, current-contract Pair 수 제한 명시 |
| Role1/Role5 사용 범위 | offline/static 및 dataset 경계 정리 완료 |
| policy stability 평가 | 완료: frozen candidate 근거 강화 |
| formal family-bound lifecycle 승격 | 후속 #234 |
| 최종 평가용 ApprovedLineagePolicy version/hash formal freeze | 미완료: #234 family binding/lifecycle 연계 후 수행 |
| holdout 이후 policy 변경 금지 lifecycle 기록 | 미완료: frozen lifecycle 확정 후 적용 |
| production runner/CLI 연결 | 후속 #228 |
| online availability/TTSD | 후속 #231/#232 |

이번 PR에서는 Pair-002 legacy baseline과 Pair-003 current-contract development Pair에 동일 selector와 policy를 적용한 multi-run development regression 범위를 완료했다. Actual telemetry에서 확인한 범위는 정상 selector, Evidence, artifact, provenance와 결정성이며, malformed fail-closed 조건은 기존 synthetic regression을 재확인한 범위다. Pair-003 raw를 가능한 fail-closed 형태로 변조해 전수 검증했다는 의미는 아니다.

#227 Issue 전체는 아직 완료되지 않았다. 최종 평가용 ApprovedLineagePolicy version/hash formal freeze와 holdout 이후 policy를 변경하지 않도록 하는 frozen lifecycle 기록이 남아 있으며, 해당 항목은 #234 family binding/lifecycle과 연계해 완료해야 한다. 따라서 #227은 Open 상태로 유지하고, production, holdout, final evaluation, online availability 또는 formal policy freeze 완료를 이번 PR에서 주장하지 않는다.
