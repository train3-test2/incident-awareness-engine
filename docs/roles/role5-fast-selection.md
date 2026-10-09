# Fast selection v1 — 역할 5 선택 경계

## 적용 범위

완료된 Fast handoff에서 Role3 `FastDetectionSelection`을 생성한다.
이 정책은 선택 알고리즘을 고정하며 후보 Rule의 decisive 적합성이나 detector set을
승인하지 않는다. 운영자는 실행 전에 승인한 set/config 대응과 host 매핑을 제공해야 한다.
기존 Adapter는 외부 selection을 계속 받을 수 있으므로 이 CLI를 우회한 선택까지
자동 검증한다고 주장하지 않는다. 해당 경로로 생성한 selection-audit를 함께 전달한다.

## v1 규칙

- 같은 Run, 명시적 canonical entity, policy로 고정한 config 해시/버전에서만 선택한다.
- runner의 qualifying RuleID allowlist를 사용한다. 추가 native context 조건은 구현하지 않는다.
  추가 조건이 필요한 후보는 이 경로의 set에 포함시키지 않는다.
- timestamp source는 Hayabusa CSV Timestamp다. UTC 밀리초로 변환된 FastHitRecord 시각을 사용한다.
  EventData.UtcTime 감사는 별도이며 이 정책은 해당 시각으로 교체하지 않는다.
- `(timestamp, rule_id, hit_id)` 오름차순의 첫 hit를 선택한다. 문자열은 Python 사전순이다.
  millisecond 변환 후 같은 시각이면 동률이다. hit_id 행 순서가 변하면 대표 hit도 변할 수 있다.
  동일 입력/설정에서는 재현되지만 행 재정렬 간 hit_id 안정성을 보장하지 않는다.
- 다른 entity의 hit는 선택하지 않는다. 매핑 불가 hit는 다른 entity 소속인지 알 수 없으므로 오류다.
- 완료 handoff에 해당 entity hit가 없으면 miss. 빈 qualifying set은 평가 수행 근거가 없어 거부한다.
- 미실행은 별도 not_evaluated 경로다. 누락/파손 artifact나 실패를 miss/미평가로 바꾸지 않는다.
- source CSV/config를 재변환해 전체 hit 목록과 대조한다. 수정 후 해시만 갱신한 hit도 거부한다.

## 외부 policy 예시 (전부 합성 값)

```json
{
  "policy_version": "fast-selection-v1",
  "detector_set_version": "synthetic-set-v1",
  "detector_config_version": "synthetic-config-v1",
  "config_sha256": "<실제 config 파일 SHA-256 64자리>",
  "timestamp_source": "hayabusa_csv_timestamp",
  "tie_break": "timestamp_rule_id_hit_id",
  "host_entity_map": {"HOST": "entity"}
}
```

이름만으로 set의 승인 여부를 인증하지 않는다. policy 자체의 진위·실행 승인과 CSV의
원본 EVTX 귀속은 제공자 책임이다.

`detector_set_version`은 식별자 형식 검증 후 audit에 보존하는 **caller-provided provenance
assertion**이다. 현재 구현은 `RunMetadata.detector_set_version`이나 승인된 detector
set↔config 대응과 직접 비교하지 않는다. 따라서 검증 완료된 set binding 또는 detector set의
승인·동결 검증으로 해석하면 안 된다. 실제로 검증하는 것은 policy의 `config_sha256`과
handoff config hash의 일치, config의 `detector_config_version` 일치 및 source CSV/config 재생이다.
같은 버전 이름에 다른 policy를 덮어쓰지 않도록 audit의 policy hash를 함께 보존한다.

```bash
uv run python -m incident_awareness.detection.fast_selection \
  --hits /local/hits.jsonl --trace /local/trace.json \
  --policy /local/selection-policy.json \
  --run-id RUN-20261008-001 --entity-id entity \
  --output-dir /local/new-selection
```

새 디렉터리만 허용한다. selection.json은 기존 Role3 Adapter 입력과 호환된다.
selection-audit.json은 policy/hash, source CSV·hits·trace 해시, 정렬된 대상 hit ID와 selection을
보존한다. 같은 부모의 임시 디렉터리에 두 파일을 모두 기록한 뒤 디렉터리를 rename하여
완료 산출물을 게시한다. 기록 또는 게시 실패 시 임시 디렉터리는 정리되며, 새 최종 경로에
부분 출력은 남기지 않는다. 동일 output-dir로 여러 프로세스를 동시에 실행하지 않는다.
소비자는 두 파일과 내용 일치를 확인하며 audit 없는 출력은 완료 산출물로 소비하지 않는다.
전체 Fast episode 생성, cooldown, causal Fusion, detector final freeze는 범위 밖이다.


## R1 실제 평가 연결 전 후속 검증

PR #241의 [set provenance 리뷰](https://github.com/train3-test2/incident-awareness-engine/pull/241#discussion_r4227079184)에 따른 미완료 항목이다.
현재 selection 생성 성공만으로 이 조건들이 충족되지는 않는다.

- [ ] RunMetadata의 detector_set_version과 selection policy/audit의 값을 비교하고,
  누락·불일치를 fail-loud로 거부한다. 다른 set으로 자동 대체하거나 miss로 처리하지 않는다.
- [ ] 승인된 set/version에 연결된 config version/hash를 확인하고 불일치를 거부한다.
  registry/동결 artifact의 승인 근거를 별도로 보존한다.
- [ ] selection audit → DetectionResult 연동 → 평가 입력까지 같은 set/config provenance가
  유지되고 검증되는지 확인한다. 현재 출력 계약에 필드가 있다고 가정하지 않고 전달 계약을 확정한다.
- [ ] 정상 대응, set mismatch, config mismatch, provenance 누락·변조 회귀 테스트를 추가한다.

위 항목은 R1 실제 평가 연결의 선행 조건이며 현재 CLI가 구현 완료한 기능이 아니다.
