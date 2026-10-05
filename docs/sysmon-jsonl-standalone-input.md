# Sysmon JSONL 단독 입력 First Cycle CLI 계약

## 범위

이 문서는 Sysmon JSONL 하나로 First Cycle Pipeline을 실행하기 위한 **개발·검증용**
CLI 계약을 정의한다. CLI는 입력 JSONL에서 RunMetadata, Manifest, Raw Log Provenance와
필요한 실행 Artifact를 생성한 뒤, 기존 First Cycle Pipeline을 호출한다. 기존 Pipeline의
정규화·Evidence·Fusion·Hybrid·PostgreSQL 저장 규칙을 우회하거나 완화하지 않는다.

이 경로는 정식 수집 Run 또는 Ground Truth Artifact를 대체하지 않는다. JSONL만으로는
시나리오의 실제 행위, `run_type`, Fast Runner 실행 여부를 알 수 없으므로, 생성 결과는
명시된 개발 실행 Profile의 결과로만 해석한다.

## CLI 입력 계약

실행 명령은 다음과 같다.

```text
python -m incident_awareness.pipeline.standalone \
  --sysmon-jsonl <path-to-sysmon.jsonl>
```

`--sysmon-jsonl`만 전달하면 `s0-standalone-v1` 개발 Profile을 적용한다. 이 Profile은
S0 Evidence·Fusion 설정을 사용해 **기술적 실행 경로를 확인하는 용도**이며, 입력이 실제
S0 공격 Run임을 주장하지 않는다.

| 항목 | 기본값 | 규칙 |
| --- | --- | --- |
| `scenario_id` | `S0` | `--scenario-id`로 명시적 변경 가능 |
| `run_type` | `attack` | JSONL만으로 자동 판정하지 않는다. `--run-type normal`로 변경 가능 |
| `target_host` | JSONL의 유일한 `Computer` 값 | 둘 이상 Host가 있으면 거부 |
| `entity_id` | `target_host` | 현재 First Cycle의 direct host mapping을 따른다 |
| Fusion Config | `configs/fusion/fusion_config_s0_pair_v0.1.yaml` | `--fusion-config`으로 명시적 변경 가능 |
| Decision Config Version | `parallel-v0.2` | 현재 지원 Hybrid 정책을 따른다 |
| Fast Mode | `not_evaluated` | Fast Runner를 자동 실행하지 않는다 |

Fusion Config는 기본값 대신 `--fusion-config`로 읽을 수 있는 유효한 Fusion 설정 파일을
명시할 수 있다. 다만 Hybrid Decision Config는 현재 `parallel-v0.2`만 허용한다. 현행
combiner가 `parallel_required=true` 정책만 구현하므로, 다른 Decision Config version이나
선택 경로 정책을 단독 입력 CLI가 추정해서 적용하지 않는다.

명시적 설정이 필요한 호출은 아래 형식을 사용한다.

```text
python -m incident_awareness.pipeline.standalone \
  --sysmon-jsonl <path-to-sysmon.jsonl> \
  --scenario-id <scenario-id> \
  --run-type <normal|attack> \
  --target-host <host-id> \
  --entity-id <entity-id> \
  --fusion-config <path-to-fusion-config>
```

현재 구현 범위에서 `--target-host`는 JSONL의 유일한 `Computer` 값과 같아야 한다. 다중
Host JSONL을 일부 Host만 골라 실행하거나 여러 Entity 결과를 한 Run에 저장하는 기능은
이 계약의 범위가 아니다.

## 자동 생성 식별자와 실행 시간

CLI는 실행 시점 UTC 날짜를 사용해 `RUN-YYYYMMDD-NNN` 형식의 `run_id`를 생성한다.
`NNN`은 PostgreSQL의 `runs.run_id`와 생성 대상 Artifact 디렉터리를 확인해 사용되지 않은
값을 선택한다. `decision_id`는 같은 Run에 대해 `DEC-<run_id>`로 생성하며, 기존
`decisions.decision_id`와 충돌하면 새 `run_id`를 선택한다.

`RunMetadata.start_time`과 `end_time`은 유효한 Sysmon 레코드의 `EventData.UtcTime` 최소·최대
값으로 생성한다. CLI는 관측 시간을 임의로 늘리거나 Evidence timestamp를 보정하지 않는다.
따라서 S0 replay 구간을 덮지 못하는 JSONL은 Fusion `not_evaluated` 결과를 만들 수 있으며,
이는 오류나 `miss`로 바꾸지 않는다.

## 자동 생성 Artifact

기본 출력 경로는 입력 JSONL과 같은 디렉터리 아래의
`.incident-awareness/first-cycle/<run_id>/`이다. `--output-dir`을 제공하면 해당 경로 아래에
같은 구조를 생성한다. 기존 `<run_id>` 출력 경로가 있으면 덮어쓰지 않고 실패한다.

```text
<output-root>/<run_id>/
├── run_metadata.json
├── manifest.json
└── telemetry/
    └── sysmon-0001.jsonl
```

생성하는 `manifest.json`은 다음 규칙을 따른다.

- JSONL의 SHA-256을 다시 계산해 Sysmon JSONL 항목에 기록한다.
- Raw Log Provenance는 `raw_log_id`, `segment_no=1`, JSONL의 1-based `record_no`를 사용한다.
- Manifest 경로는 현재 First Cycle 검증기가 요구하는
  `raw/<run_id>/telemetry/sysmon-0001.jsonl` 꼬리 경로를 사용한다.
- 입력이 EVTX에서 export된 사실을 증명하는 EVTX 바이트는 생성하지 않는다. Manifest의
  EVTX 참조는 JSONL의 논리적 `derived_from` 관계를 표현할 뿐이며, 원본 EVTX의 보관·검증은
  정식 수집 경로의 책임이다.

생성 직후 CLI는 기존 `RunMetadata`, Manifest SHA-256, Sysmon JSONL reader, Normalizer
입력 검증을 적용한 뒤 Pipeline에 전달한다.

## Sysmon 입력 제한

현재 First Cycle Normalizer가 지원하는 Sysmon Event ID는 아래 둘뿐이다.

| Event ID | Event Type | 필수 시간·Host 입력 |
| ---: | --- | --- |
| `1` | `process_create` | `TimeCreated`, `Computer`, `EventData.UtcTime` |
| `3` | `network_connection` | `TimeCreated`, `Computer`, `EventData.UtcTime` |

JSONL의 모든 줄은 JSON object여야 하고, 빈 줄·손상 JSON·지원하지 않는 Event ID·다중 Host는
거부한다. `EventData.UtcTime`은 UTC로 해석 가능한 Sysmon 시간이어야 한다.

수집기는 원본 Sysmon `RecordId` 순서를 JSONL의 물리적 줄 순서로 보존한다. 이 순서는
`EventData.UtcTime` 순서와 다를 수 있으므로, standalone은 원본 JSONL·SHA-256·1-based
`record_no`를 변경하지 않는다. 대신 정규화와 시간 기반 Fusion 처리 직전에 `EventData.UtcTime`,
`RecordId`, 원본 `record_no` 순으로 안정 정렬한다.

## Fast와 Decision 결과 경계

기본 `not_evaluated` 모드는 Fast Runner를 호출하거나 FastHit Artifact를 추정 생성하지
않는다. 생성되는 `DetectionResult.detector_status`는 `not_evaluated`이며 Fast 판단 시각은
`null`이다. 따라서 단독 입력 orchestration은 기존 `load_s0_fast_detection()`의 Fast
handoff reader를 호출하지 않고, `build_not_evaluated_detection_result()`를 통해 Fast 결과를
만든 뒤 기존 Hybrid·Persistence 단계로 전달한다.

현행 Hybrid 구현은 `parallel_required=true`만 지원한다. 따라서 기본 모드에서 Fusion이
`detected` 또는 `miss`여도 `DecisionResult`는 유효하게 저장되지만, `t_e`,
`decision_path`, `winning_path`는 모두 `null`이다. 이것은 Fast 경로가 완료되지 않은
상태를 보존하는 결과이며 Fusion 단독 탐지로 재해석하지 않는다.

Fast Runner 자동 실행은 역할 5가 안정적인 CLI·입출력·Config 계약을 제공한 뒤 별도
`--fast-mode runner`로 추가한다. 이미 완성된 Fast handoff를 사용하려는 경우에도 이 단독
입력 계약을 확장하지 않고, 기존 First Cycle 입력 Artifact 경로를 사용한다.

## PostgreSQL과 AWS 경계

CLI는 기존 Pipeline처럼 `INCIDENT_AWARENESS_DATABASE_URL`이 설정된 PostgreSQL에 Run,
Event, Fusion, Detection, Decision을 하나의 트랜잭션으로 저장한다. DB URL이 없으면
"결과까지" 실행을 주장할 수 없으므로 실행을 시작하지 않는다.

AWS 실행은 이 CLI가 생성한 `<output-root>/<run_id>/` Artifact를
`s3://<bucket>/first-cycle/<run_id>/`로 업로드한 뒤 기존 First Cycle ECS Task를 실행하는
방식을 사용한다. S3·ECS 실행 절차는 [AWS First Cycle 입력 Artifact 계약](aws-first-cycle-inputs.md)과
[GitHub Actions AWS 실행 가이드](github-actions-smoke-deploy.md)를 따른다.

## 실행 전제와 후속 작업

- CLI는 `INCIDENT_AWARENESS_DATABASE_URL`과 적용 완료된 First Cycle migration을 요구한다.
  실행 시 PostgreSQL의 `runs`, `decisions`와 출력 경로를 함께 확인해 사용하지 않은 `run_id`,
  `decision_id`를 할당한다.
- 생성 Artifact는 기본 출력 경로 또는 `--output-dir` 아래에 보존한다. 기존 Run 출력 경로는
  덮어쓰지 않는다.
- `s0-standalone-v1` 외 시나리오를 기본값으로 제공하려면 해당 시나리오의 Evidence·Fusion·Fast
  Config와 입력 제한을 별도로 확정한다.
- 다중 Host JSONL, 여러 JSONL segment, 실제 Fast Runner 자동 실행은 별도 실행 Config와
  결과 저장 범위가 필요하다.
