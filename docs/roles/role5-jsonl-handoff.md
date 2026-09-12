# #46 First Cycle JSONL 전달부

최신 develop의 기존 Hayabusa adapter를 호출한다. 탐지 엔진 실행·DetectionResult 생성·
entity_id 매핑·detector_time 계산·Hybrid 결합은 이 runner에서 수행하지 않는다.

## 실행

저장소 루트에서 출력 폴더를 먼저 만든다. 출력·trace는 기존 파일을 덮어쓰지 않는다.

```bash
mkdir -p /tmp/role5-handoff
PYTHONPATH=src uv run python -m incident_awareness.detection.fast_runner \
  --csv tests/fixtures/detection/handoff.csv \
  --config tests/fixtures/detection/handoff_config.json \
  --run-id RUN-20260913-001 \
  --output /tmp/role5-handoff/hits.jsonl \
  --trace /tmp/role5-handoff/trace.json
```

fixture는 인공 CSV이며 실제 Hayabusa 탐지나 normal/pilot 성능을 증명하지 않는다.
mock-rule은 연동 테스트용이며 #44 detector freeze가 아니다.
실제 실행 시 역할 3에서 전달한 run_id와 실행 설정을 사용한다.
설정 JSON은 runner 전용 설정이며 공통 결과 Contract를 추가하지 않는다.

## 전달과 provenance

- `hits.jsonl`: 기존 FastHitRecord 필드만 포함. 역할 3 Fast Adapter에 전달한다.
- `trace.json`: 원본 CSV·설정 해시, 원본 행 번호와 hit_id, 출력 해시를 보존하는 조사용 sidecar.
- 원본 CSV와 설정도 보관한다. 해시만으로 원본을 복원할 수 없다.
- Run당 단일 통합 CSV를 한 번 변환하는 First Cycle 전제다. 여러 호출 결과를 같은
  run_id로 합치지 않는다. 임시 행 순번 ID는 입력 순서 변경 시 안정성을 보장하지 않는다.
- 빈 JSONL은 qualifying row가 없다는 뜻이며, 미실행과 miss 구분은 실행 context와
  역할 3 계약에서 처리한다. 이 파일만으로 DetectionResult miss를 생성하지 않는다.
- run_id는 기존 RunMetadata의 형식·날짜 검증을 재사용한다. Ground Truth는 읽지 않는다.

## 수신 검증 상태

역할 5 전달부 테스트와 실제 역할 3 수신은 구분한다. 확인한 develop 및
origin/feature/data-pipeline/mock-hybrid-decision에는 실제 Fast Adapter 호출 경로가
확인되지 않았다. 담당자의 로컬 구현까지 없다는 뜻은 아니다.
실제 진입점 확보 후 동일 run_id, native 필드, 버전, hit_id provenance 보존을 확인한다.
현재는 DetectionResult·DecisionResult/t_e 생성과 Mock E2E 완료를 주장하지 않는다.
