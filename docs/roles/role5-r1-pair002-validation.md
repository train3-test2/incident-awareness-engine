# Pair-002 development 연결 검증 (2026-10-06)

## 범위와 데이터 사용

최신 develop `3f0cdb5`의 기존 normalizer, R1 extractor, artifact writer/reader를 실행했다.
관련 #184, #73. 이 기록은 해당 이슈 전체 완료나 공식 Pilot pass가 아니다.

Pair `R1-PAIR-20261005-002`: Attack `RUN-20261005-912`, Normal `RUN-20261005-913`.
최종 승인 전 수집과 실제 값 검토·후보 실행 이력을 고려해 **development tuning 전용**으로 관리한다.
공식 development 수량, train/validation/test, holdout 및 최종 성능 평가에서 제외한다.
원본 index의 과거 `used_for_diagnostic_or_tuning=false`는 덮어쓰지 않고,
[별도 사용 기록](validation/r1-pair002-data-usage.json)에 현재 `used_for_tuning=true`를 남긴다.
원본 EVTX/JSONL·실행 기록·metadata와 실제 생성 Evidence는 저장소에 게시하지 않는다.

## 무결성 및 reference 선행 확인

로컬 선행 감사에서 배포 해시·ZIP CRC 및 해제 파일·manifest·reference 등 80개 검사를 통과했다.
이는 공식 Python 3.13 수집 validator 전체 검사를 대신하지 않는다.
Attack reference는 A01 wsmprovhost.exe EID 1 RecordID 1275,
`EventData.UtcTime=2026-10-05T19:33:26.037Z`이며 Normal reference 세 필드는 null이다.
정책은 `r1-ref-v0.1`, horizon 600초다. metadata 관측 종료가 horizon을 포함하는 것과
telemetry completeness가 입증되는 것은 별개다.

## 실제 Hayabusa 후보 실행

Hayabusa 4.0.0 mac aarch64, 아래 **원본 룰 하나**를 두 EVTX에 동일하게 적용했다.

- `proc_creation_win_powershell_script_engine_parent.yml`
- Suspicious PowerShell Invocation From Script Engines
- Rule ID `e930e38b-863b-1453-7940-7d3b2a611b2d`
- 룰 SHA-256 `87599e02f2468c47b1f317ff025c29fb52a6b3d90a8d545529dca05abb2f48f4`
- 엔진 SHA-256 `e8b02a0908920f656e99d4968ca4a3d382942158679ab371ac2db103c27ebe83`
- 명령: 엔진 디렉터리에서 `./hayabusa-4.0.0-mac-aarch64 dfir-timeline -f <EVTX> -r <RULE> -w -O -t csv -K -o <새 CSV>`

| Run | EVTX 스캔 | 후보 hit | RecordID |
|---|---:|---:|---|
| Attack 912 | 98 | 1 | 1327 |
| Normal 913 | 97 | 0 | 없음 |

양쪽 exit 0, 채널 필터 이후 활성 룰 1개를 실행 로그로 확인했다. Normal CSV는 0바이트였다.
원본 EVTX와 룰의 전후 해시는 동일했다. 후보 조건은 수정하지 않았다.

Attack hit의 CSV Timestamp는 `2026-10-05T19:38:26.260315Z`,
원본 EventData.UtcTime은 `2026-10-05T19:38:26.253Z`로 **7.315ms 차이**가 있다.
최종 R1 detector_time 산출 시 CSV 시각을 무조건 채택하면 안 된다.
현재는 candidate hit일 뿐 qualifying set 동결/DetectionResult/selection 산출이 아니다.
Normal 한 번의 0 hit를 FP 검증 완료로 해석하지 않는다.

## 정규화 → Evidence 실제 결과

| Run | 정규화 | EID 1 / 3 | 계보 RecordID | t+8 RecordID | 계보 이탈 / 후속 연결 Evidence |
|---|---:|---|---|---|---|
| Attack 912 | 98 | 74 / 24 | 1275 → 1325 → 1327 | 1350 | 1 / 1 |
| Normal 913 | 97 | 73 / 24 | 1290 → 1335 → 1337 | 1373 | 0 / 1 |

- Attack: wsmprovhost.exe → cscript.exe → powershell.exe.
- Normal: wsmprovhost.exe → cmd.exe → powershell.exe.
- EventData.UtcTime, 별도 record_time, ProcessGuid, EID 1 ParentProcessGuid/CommandLine,
  source RecordID, raw_log_id/물리적 줄 번호, EID 3 목적지 IP/port 보존을 검증했다.
- 각 terminal과 승인 목적지 EID 3의 ProcessGuid가 일치한다.
- Evidence.event_ids → NormalizedEvent → 원본 RecordID가 모두 연결되며 Run/host/시각을 교차 검증했다.
- 양쪽 `diagnostics=[]`, `telemetry_completeness=not_provided`다.
  진단 없음은 선택한 계보의 추출 정상 완료이며 전체 수집 완전성 보증이 아니다.
- Normal에도 후속 연결 Evidence가 있다. Evidence 발생 자체는 공격 판정이 아니다.

[기계 판독 결과 및 입력 해시](validation/r1-pair002-connection.json)

## 재현과 selector 한계

```bash
uv sync --locked
INCIDENT_AWARENESS_EVENT_TYPES_PATH=configs/event_types_v0.2.yaml \
PYTHONPATH=src uv run python tools/validation/check_r1_pair_connection.py \
  --pair '<로컬 Pair-002 디렉터리>' --output '<존재하지 않는 출력 디렉터리>'
```

출력은 Run별 `normalized_events.jsonl`, `r1_evidence.jsonl`,
`r1_extraction_summary.json`과 공통 `connection-report.json`, `audit-policy.json`이다.
실패 후 부분 출력이 있으면 새 디렉터리로 재실행한다. 성공은 connection-report와 종료 코드로 확인한다.

이 도구는 **연결 감사용**이다. execution_record의 A01/N01 ±2초로 session anchor,
A03/N03 ±2초로 terminal, A04/N04 ±2초와 승인 목적지로 연결 후보를 고른다.
양 끝을 포함하고 후보가 정확히 하나가 아니면 실패한다. Ground Truth 실행 시각을 이용하므로
production selector/최종 평가 detector로 재사용하면 안 된다.

계보 정책은 기존 `docs/evidence/evidence-type-r1-v02.md`의 정상 계보를 그대로 사용한
감사용 `r1-v02-development-connection/v0.1`이다. 실제 Pair에서 정상 계보를 학습하거나
Attack hit에 맞춰 바꾼 것이 아니며, 공식 운영 정책 freeze를 의미하지 않는다.
정책 hash는 줄바꿈 없는 canonical JSON을 기준으로 한다.

## 후속 경계

실제 Evidence를 Fusion/Weighted Rule/Static ML에 넣기 전 vocabulary와 설정 버전을 확인해야 한다.
Fast에는 EventData.UtcTime 기반 provenance 연결과 qualifying set의 별도 결정이 남아 있다.
이 Pair를 최종 성능 데이터로 승격하거나 #184 전체를 닫지 않는다.

## 코드 검증

Python 3.13 전체 pytest: **2,547 passed / 91 skipped**.
신규 5개 검사는 실제 pipeline 연결, ±2초 포함 경계, 중복 terminal 거부,
입력 해시 불일치 거부, 끊긴 계보 거부 및 extractor의 truncated 진단을 확인한다.
Ruff check/format과 git diff --check 통과.

## 후속: Fast 후보 시각의 유일한 원본 연결

`tools/validation/check_fast_candidate_time.py`는 `Computer + Channel + RecordID` 전체 키로
CSV 후보를 원본 JSONL 한 건에 연결한다. Hayabusa의 `Sysmon` 표기만
`Microsoft-Windows-Sysmon/Operational`로 명시적으로 변환한다.
키가 누락되거나 대응 레코드가 0건/복수이면 오류이며 EventID도 교차 검증한다.
`EventData.UtcTime`이 없거나 잘못되면 TimeCreated로 대체하지 않는다.

```bash
uv run python tools/validation/check_fast_candidate_time.py \
  --run-id RUN-20261005-912 --csv '<candidate-hits.csv>' \
  --raw-jsonl '<동일 Run의 sysmon-0001.jsonl>' --output '<새 time-link-validation.json>'
```

실제 Pair 실행: Attack의 RecordID 1327이 유일하게 연결되며 CSV와 UtcTime 차이는
정수 **7,315µs**다. Normal CSV는 후보 0건으로 빈 연결 목록을 생성한다.
0건을 Fast miss로 변환하지 않으며 `final_detector_time=null`을 유지한다.
입력 파일의 SHA-256과 원본 JSONL 줄 번호를 결과에 기록한다.
원본에 run_id 필드가 없으므로 같은 Run의 두 파일을 제공할 책임은 호출자에게 있으며,
출력 run_id가 원본에서 검증됐다고 주장하지 않는다.

신규 시각 연결 테스트 10개 및 기존 연결 테스트 5개, 합계 15개 통과.

## Baseline 입력 준비 및 동일 Run 시간 대조

[입력 목록](validation/r1-pair002-input-inventory.json)은 Run별 Evidence·추출 summary·정규화 Event·metadata·Fast 시각 연결 파일의 SHA-256,
extractor 버전, 관측 범위와 tuning 용도를 기록한다. 정확한 로컬 경로는 별도 로컬 산출물의
input-inventory.json에 보존하며 저장소에는 경로 placeholder를 사용한다.
기존 artifact reader 검증과 Fast 원본 JSONL 해시 일치 검사를 다시 통과했다.

| Run | 관측 범위 (UTC) | 관측 길이 | Evidence / extractor |
|---|---|---:|---|
| Attack 912 | 19:33:25.834 ~ 19:44:28.494 | 662.660초 | 2 / r1-v0.1 |
| Normal 913 | 19:56:52.355 ~ 20:07:54.631 | 662.276초 | 1 / r1-v0.1 |

모두 2026-10-05이며 development tuning 전용이다. 모델 학습·validation·test 입력으로 사용하지 않는다.
공통 vocabulary와 window/cadence/feature 설정이 아직 준비되지 않았으므로 입력 목록 작성이
Baseline 실행 가능 또는 성능 평가 준비 완료를 의미하지 않는다.

### Attack 912 타임라인

| 항목 | UTC | reference 이후 | 관측/600초 horizon 내 |
|---|---|---:|---|
| A01 reference | 19:33:26.037 | 0초 | 예 |
| Fast 후보 및 계보 이탈 Evidence | 19:38:26.253 | 300.216초 | 예 |
| 후속 연결 Evidence | 19:41:26.617 | 480.580초 | 예 |
| horizon 종료 | 19:43:26.037 | 600초 | 예 |
| 실제 관측 종료 | 19:44:28.494 | 662.457초 | 관측 내, horizon 밖 |

Fast 후보와 계보 이탈 Evidence가 동일 원본 RecordID 1327의 이벤트 시각에 도달한다.
Evidence 생성 시각은 Fusion 판단 시각이 아니다. 위 상대 시간은 후보/증거 시점의 위치이며 TTSD가 아니다.
동일 Run FusionResult가 없으므로 Fusion 선행/지연 시간은 계산하지 않았다.

### Normal 913 및 범위 밖 입력

Normal의 후속 연결 Evidence는 20:04:52.808Z이고 관측 범위 안이다.
reference 세 필드는 null을 유지하며 attack용 600초 horizon이나 상대 reference 시각을 만들지 않는다.

두 Run 모두 정규화 이벤트 6건씩이 metadata.start_time 이전에 존재한다.
Attack RecordID: 1269~1274, Normal: 1287~1289 및 1291~1293.
이번에 생성한 Evidence의 event_ids에는 이 레코드가 참조되지 않는다.
관측 종료 이후 이벤트는 없다. 원본은 삭제하지 않는다. 후속 replay에서 선언한 분석 범위와
warm-up 사용 여부를 명시해야 하며, 범위 밖 이벤트를 무조건 입력하거나 조용히 제거하지 않는다.

로컬 재현 산출물: input-inventory.json, comparison-timeline.json, build.py.
검증 시각과 해시는 고정된 Pair-002 입력에 대한 것이며 운영 모델 설정 동결은 아니다.
