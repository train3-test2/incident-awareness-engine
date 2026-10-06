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
