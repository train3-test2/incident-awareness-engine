# R1 자동 Evidence 실행 경로 v0.1

> 상태: development/offline high-level orchestration
> availability: `OFFLINE WHOLE-EPISODE ONLY`
> 비범위: production runner/CLI, causal online input, Fusion/Role5 평가, formal evaluation 실행

## 1. 목적

`src/incident_awareness/pipeline/r1_automated.py`는 이미 구현된 selector, approved policy loader, R1 Evidence pipeline, artifact writer를 하나의 반복 가능한 development/offline 경로로 연결한다. 새 selector, Evidence 의미, artifact format 또는 policy hash 규칙을 정의하지 않는다.

```text
NormalizedEvent batch
→ scenario family metadata
→ repository-managed ApprovedLineagePolicy loader
→ family binding validation
→ deterministic selector
→ anchor / terminal
→ R1LineageInput
→ existing R1 Evidence pipeline
→ existing immutable artifact writer
→ r1_evidence.jsonl / r1_extraction_summary.json
```

## 2. Public API

### Evidence 실행

`run_r1_evidence_pipeline_from_policy()`는 다음 입력을 받는다.

- `NormalizedEvent` iterable
- `R1SelectorPolicy`
- approved policy `policy_id`와 `version`
- 선택적인 repository config path override
- family-bound policy를 사용할 때 rendered scenario의 `scenario_family_id`

입력을 materialize하고 `load_r1_approved_lineage_policy()`로 policy를 로드한다. Family-bound policy는 공용 validator로 scenario family 일치를 확인한 뒤에만 `run_r1_evidence_pipeline_with_selector()`를 호출한다. 반환형은 기존 `R1SelectedEvidencePipelineResult`이므로 Evidence, selector result, 생성된 `R1LineageInput`, extraction diagnostics를 그대로 확인할 수 있다.

### Artifact 실행

`run_and_write_r1_evidence_artifacts_from_policy()`는 Evidence 실행 입력에 `run_id`와 빈 output directory를 추가로 받아 기존 `run_and_write_r1_evidence_artifacts()`를 호출한다. `R1AutomatedEvidenceArtifactRun`은 runtime selector 결과와 기존 `R1EvidenceArtifactRun`을 함께 반환한다. 기존 manual API와 artifact filename/schema는 변경하지 않는다.

## 3. 책임 경계

- Selector는 이름, PID, Ground Truth, `run_type`, Attack/Normal label 또는 Pair별 RecordId 없이 구조적으로 anchor와 terminal을 선택한다.
- Approved policy loader는 repository config validation, policy identity lookup, canonical hash 계산의 유일한 source of truth다. Orchestration은 YAML을 직접 parse하거나 hash를 재계산하지 않는다.
- Family-bound policy의 `scenario_family_id` mismatch와 누락은 selector 실행 전에 configuration 오류로 거부한다. Family mismatch를 selector diagnostic으로 변환하지 않는다.
- 기존 R1 Evidence pipeline은 selector가 만든 `R1LineageInput`으로 lineage deviation과 terminal GUID 기반 network follow-on을 생성한다.
- Artifact writer는 기존 immutable JSONL/summary 계약, canonical ordering, SHA-256과 lineage/policy provenance를 유지한다.

`selector_policy.lineage_event_count`와 `approved_policy.approved_lineage` 길이가 다르면 기존 selector pipeline 경계에서 Event 선택 전에 `ValueError`로 거부한다.

## 4. Fail-closed와 provenance

- 알 수 없는 policy, malformed config, 중복 identity, 잘못된 lineage 또는 family mismatch는 selector, Evidence, artifact writer를 실행하기 전에 실패한다.
- Selector가 no candidate, ambiguity, temporal inversion, truncated lineage 또는 duplicate GUID로 실패하면 Evidence를 생성하지 않는다. 구조화된 selector diagnostics는 `R1AutomatedEvidenceArtifactRun.pipeline_result.selector_result`에 유지한다.
- 자동 실행 summary의 `selector`에는 selector policy ID/version/config hash, `selected` 또는 `failed` status와 selector diagnostics를 기록한다. Selector 성공 시 선택된 anchor/terminal과 approved policy provenance는 기존 `lineage_inputs`에 기록해 중복하지 않는다.
- 기존 manual artifact는 `selector` 필드를 생략하며 새 loader는 selector 필드가 없는 기존 artifact와 새 자동 실행 artifact를 모두 읽는다.
- Artifact publication과 재시도는 기존 writer의 immutable output 및 failed-summary 계약을 그대로 따른다.

Selector 실패 후 생성되는 빈 artifact는 `evidence_count = 0`, `selector.status = failed`와 non-empty `selector.diagnostics`를 함께 기록한다. 따라서 artifact consumer는 selector 정보가 없는 기존 manual 0건 또는 `selector.status = selected`인 자동 실행 결과와 fail-closed 0건을 구분할 수 있다. 기존 summary의 `diagnostics`는 lineage extraction 진단 의미를 유지한다.

## 5. 결정성과 manual API 호환

동일한 NormalizedEvent 집합, selector policy, approved policy identity/config와 실행 코드에 대해 selection과 Evidence identity/content는 동일하다. 기존 writer가 보장하는 canonical 직렬화 범위에서는 별도 빈 output directory에 생성한 artifact bytes도 동일하다. 입력 Event 순서는 이 의미를 바꾸지 않는다.

다음 기존 API는 그대로 유지한다.

- `ApprovedLineagePolicy(...)`
- `R1LineageInput(...)`
- `run_r1_evidence_pipeline(...)`
- `run_r1_evidence_pipeline_with_selector(...)`
- `run_and_write_r1_evidence_artifacts(...)`

새 API는 기존 수동 경로를 대체하는 migration이 아니라 policy 객체와 lineage input 조립을 줄이는 편의 경로다.

## 6. 현재 제한과 후속 작업

- 이 경로는 caller가 제공한 whole-episode batch를 한 번에 처리하는 development/offline API다. Production runner/CLI 연결은 #228 범위다.
- Evidence timestamp는 semantic Event time이며 causal `available_at`이 아니다. Availability/watermark는 #231, Temporal Replay/TTSD는 #232 범위다.
- Approved policy v0.2는 family binding과 lifecycle 계약을 제공한다. Registry에는 development `v0.2`와 formal pre-holdout 승인을 받은 frozen `v0.3`을 별도 identity로 등록했다. Historical v0.1 unbound policy는 기존 재현 경로에서만 유지한다.
- Development 실행은 development policy를 사용하고 formal evaluation은 frozen policy를 명시적으로 선택한다. Production policy 승인, 여러 정상 lineage 표현, analysis window, Fusion scoring과 Role5 evaluation은 이 경로가 결정하지 않는다. Production runner 연결은 #228 범위다.
