# KISA DOCX 전용 품질 보완

2026-10-20, `feature/dashboard/demo-polish`.
최신 범위는 **DOCX 단일 출력**이다. PDF 생성·변환·미리보기·다운로드 UI 및 HWP 변환은
이번 범위에서 제외했다. 기존 PDF 파일과 다른 기능이 사용하는 공통 모듈·의존성은 보존했다.

접속: **http://127.0.0.1:8804/dashboard**.

## 결과와 파일

개선 샘플:
`build/kisa-docx-quality/samples/run007-other-hacking/KISA_침해사고_신고서_RUN-20261019-007_v2.docx`.
실제 Run 007의 저장 ReportDraft v6을 복제 원장에서 사용한 **개발 검증용 양식 v2**다.
기존 실제 원장에 유형 선택·입력·동의·t_h를 대신 기록하지 않았다. 기존 v1 파일도 보존했다.

Word 16 인쇄 레이아웃에서 실제 007 사본은 2페이지이며 마지막 대응 행 또는 빈 페이지가
고립되지 않는다. 기업명 입력 셀을 별도 사본에서 수정하고 저장·재열기를 확인했다.
기존 3페이지 PDF를 다시 변환한 결과가 아니라 DOCX를 직접 연 Word의 페이지 구성이다.
DOCX/Word 검증에서는 PDF를 생성하지 않았다. LibreOffice/PDF 변환 검증도 최신 지시에 따라 수행하지 않았다.

검증 산출물은 `build/kisa-docx-quality/word-accepted/<case>/`에 있다.
`word-validation.json`은 원본 DOCX SHA-256, Word 버전·페이지 수, 입력 셀 편집·재열기,
본문 전체 존재, 바닥글 일치, 마지막 페이지 고립 검사 결과를 연결한다.
`page-*.png`/`page-*.emf`는 Word 페이지 객체에서 얻은 개발 검증용 화면 자료다.
사용자 다운로드 형식으로 제공하지 않는다. `samples.json`에는 문서와 원천·양식 버전,
해시·분류 기록·미완료 상태를 연결했다.

## Word 레이아웃

원본 SHA는 `191da8b91ecf311070a5d9479fbef38f28245a6eba2df9781ad4694d4bdeac78`로 유지한다.
원본 표 개수·물리 행·그리드 너비·셀 수·`gridSpan`·`vMerge`를 비교했다.
원본 로고·머리글·스타일 파트는 바이트 단위로 유지하며 필수 법령·동의·첨부 안내와 예시를
삭제하지 않는다. 새 문서의 렌더러 버전은 `kisa_docx_renderer_v3`다.

행의 큰 최소 높이를 내용에 맞추고, 빈 간격 문단·문단 전후 간격·셀 위아래 여백을 정리했다.
표 문단의 문서 격자 강제를 해제하고, 기본 크기가 불명확했던 입력 run은 10pt로 명시했다.
기존 8·9pt 안내·예시 글꼴은 유지한다. 본문을 작게 축소해 페이지 수를 강제하지 않는다.

짧은 기업 조치사항은 피해 IP·도메인 문맥 및 원래 안내문과 함께 이동한다. Word의 병합 셀
유지 규칙에 따라 더 큰 사고현황 구역이 함께 넘어갈 수 있다. 따라서 다른 유형·긴 관측
설명이 있는 합성 사례는 3페이지, 긴 여러 줄 조치 사례는 4페이지일 수 있다.
긴 대응 문단은 행·문단 분할을 허용한다. 모든 문서를 2페이지로 강제하지 않는다.

표 뒤에는 Word가 필요로 하는 빈 종결 문단을 명시하고, 그 **빈 문단 표시만** 1pt로 처리해
빈 마지막 페이지를 방지한다. 사용자에게 보이는 본문이나 안내문을 1pt로 만들지 않는다.
표 머리행은 다음 페이지에 반복한다.

매 페이지 바닥글에 다음을 표시한다.

> 개발용 시나리오 · 검토용 초안 · 실제 외부 제출되지 않음

버전·Run·담당자 선택 양식·검토 전 표시도 바닥글로 옮겼다. 원본 머리글 로고와 본문 표는
유지한다. 이를 위해 `word/footerKisaDraft.xml`과 관계·Content Type 항목을 추가하고
default/first/even 바닥글 참조를 연결했다. 문서 본문 외에는 위 관계·타입 파일만 변경하며
원본 ZIP 파트들은 유지한다. ZIP 타임스탬프도 고정해 동일 입력 렌더링을 재현할 수 있다.

## 사고내용과 근거 검증

본문은 확인 가능한 행동 설명을 우선한다. Fusion 상태·점수·이벤트 869건·Episode 수는
기존 기술 증빙 snapshot에 남기고 본문에서 반복하지 않는다.

Run 007은 Evidence 원문 연결이 아직 검증되지 않았으므로 다음과 같이 기록한다.

> 개발용 침해 의심 사례입니다. 실제 사고·피해는 확정되지 않았습니다.
> 상세 행위 미확인: Evidence 원문 연결이 검증되지 않았습니다.

프로세스·명령행·네트워크 연결을 문장으로 만들려면 저장 snapshot 안에서 다음이 모두 맞아야 한다.

- Evidence가 VERIFIED이며 실제 Evidence ID가 있다.
- Source Event ID가 해당 Evidence 참조와 일치한다.
- 양쪽 RawLogReference 전체가 일치하고 이벤트의 raw_content_verified가 true다.
- 이벤트의 Run·관측 시스템이 원천 초안과 일치하고 관측 시각에 시간대가 있다.
- ProcessInfo 또는 NetworkInfo 계약에 맞는 실제 관측값이 있다.

이 조건을 통과한 프로세스명·명령행·연결 목적지만 인용 데이터로 문장화한다. 관측 시각은
관측 시각으로, 시스템은 관측 시스템으로 표시한다. 이를 사고 발생시각·피해 시스템·피해 IP로
바꾸지 않는다. 현재 실제 아카이브 resolver를 구현하거나 미검증 링크를 VERIFIED로 바꾸지는
않았다. 해당 경로는 완전한 합성 체인으로 시험했다.

KISANarrative JSON과 MonoRouter requests Adapter는 유지했다. 생성 문장·역할·근거 ID는
정본과 대조하고 없는 원인·피해·유출·복구 주장은 거부한다. 로그의 명령형 문자열도 인용 데이터로
취급한다. LLM이 새로운 유형·t_h·기업정보를 정하지 않는다.

실제 Run의 외부 전송 차단은 유지했다. 현재 007 문서는 Jinja2 fallback이며 해당 사실을
화면에 표시한다. 이번 작업에서는 실제 외부 LLM 호출을 하지 않았다. 기존 합성 연결 성공
이력은 보존하고 새 계약의 성공/timeout/429/출력 불일치는 모의 전송으로 검증했다.

## 미입력·확인불가·제출 준비

신규 양식은 `kisa_form_data_v2`를 저장한다. 기존 `confirmation_status`와 근거·actor/action은
유지하면서 다음 `input_state`를 추가했다.

| 상태 | 의미 | 예 |
|---|---|---|
| missing_input | 담당자의 입력·기록 대기 | 기업명·연락처 미입력, t_h 미기록 |
| unknown | 기술적으로 미확인 또는 담당자가 확인불가로 기록 | 발생시간·피해 IP 미확인 |
| confirmed | 담당자 확인값·저장 grounded 사실·저장 t_h | 확인한 신고자 정보 |

확인불가를 명시적으로 기록한 사실은 기존 CONFIRMED_UNKNOWN으로 별도 보존한다.
따라서 기술 지식의 unknown과 사람의 확인 여부도 구분된다. 기업·신고자 입력 대기를
기술적으로 확인할 수 없다고 판단하지 않는다. DOCX에는 미입력, 기술적 미확인에는 원본의
확인불가를 사용한다. 미선택 체크박스는 자동 체크하지 않는다.

`assess_readiness`는 필수 항목별 label/state/target, missing_inputs, unknown_fields,
field_states, blockers를 제공한다. 문서 파일 생성 성공은 제출 준비 완료가 아니다.
현재 007은 t_h·조직·신고자·주요 동의/확인이 미완료이며 제출 준비 미완료로 표시한다.
개발용 문서의 submission_ready는 항상 false다.

기존 GET `/kisa-forms`에 다음을 추가했다. 기존 items의 저장 JSON·해시는 바꾸지 않는다.

- `readiness_assessments`: 이전 버전에도 적용하는 읽기 전용 평가.
- `unsaved_preview`: 저장 전 누락 평가. 실제 담당자 행위·분류·t_h를 생성하지 않는다.

Dashboard는 서버의 누락 목록을 항목별로 표시하고 해당 입력칸을 열어 이동한다.
t_h 항목은 기존 Human Workflow 기록 버튼으로 포커스를 옮길 뿐 클릭·기록을 대신하지 않는다.
t_h를 기록한 뒤에는 새 Workflow 버전에 맞는 원천 초안이 필요함을 안내한다.
입력한 값은 확인 상태를 명시해야 저장한다. 미저장 값은 다운로드에 섞이지 않는다.

신규 `classification`에는 담당자가 선택한 유형·사유, actor/action/기록시각, 원천 SHA가 있다.
이를 양식 snapshot·버전·DOCX 해시와 연결한다. 렌더러는 입력 유형·사유와 분류 기록의
actor/action/source가 일치해야 체크박스를 선택한다. Fusion detected만으로 유형을 고르지 않는다.

## UI·데이터 보존

사고 유형 선택 → 누락 확인·입력 수정 → 근거 기반 사고내용 생성 → 저장 초안 확인 →
Word 다운로드를 제공한다. 실제 LLM 사용 여부·모델·fallback 상태는 실제 생성 메타데이터를 따른다.
다운로드 후 Word에서 수정할 수 있으며 편집본 재업로드는 이번 범위에 추가하지 않았다.

PDF 링크·버튼·사용 안내는 Dashboard에서 제거했다. 기존 분석 PDF 파일·원장과 공통
PDF 모듈·레거시 API는 다른 기능의 호환을 위해 보존했으며 새 DOCX 경로에서는 호출하지 않는다.
기술 JSON은 별도 근거 참조용 API이며 신고서 출력 형식은 DOCX다.
검증 중 기존 `workflow-report-ux/samples/`가 비어 있는 것을 확인했다. 작업 전 SQLite의
캐시에 남아 있던 기존 v6 실제 개발 샘플·v2 합성 PDF를 이전 검증 manifest의 SHA-256과
대조한 뒤 같은 바이트·파일명으로 복원했다. 생성·변환이나 기존 DB 수정은 하지 않았다.
상세 기록은 `legacy-pdf-preserved.json`이다. 새 DOCX 검증 폴더에는 PDF가 없다.

PostgreSQL Migration과 SQLite 스키마 변경은 없다. 작업 전 online SQLite backup과
PostgreSQL 전체 행·스키마·함수 snapshot을 `build/kisa-docx-quality/`에 저장했다.
`preservation-result.json`에서 기존 전체 행·스키마와 원본 DOCX/HWP·기존 v1 산출물 해시를
대조한다. 실제 007은 Workflow v3·감사 3건·t_h null, 006/008은 알림 0건이다.

테스트 입력·인지시각·동의·분류는 소유 임시 PostgreSQL 및 복제 SQLite에서만 작성했다.
기존 8794/8795/8797/8798/8801/8803 서버를 보존했고 새 8804만 검증 코드 갱신을 위해
재시작했다. Docker Volume·기존 Run/Fusion/Decision·기존 초안·PDF·미커밋 코드는 보존한다.
Git reset/clean/stash/commit/push/merge와 실제 AWS·KISA 제출은 수행하지 않았다.

## 검증과 변경 파일

검증 로그: `full-final-tests.log`, `target-tests.log`, `ui-tests.log`, `postgres-tests.log`,
`browser-real.json`, `browser-isolated.json`, `server-restart.json`, `word-accepted/word-summary.json`.
실제 브라우저 검증은 누락 표시·입력 상태·기본 미동의·DOCX 다운로드/해시·이전 버전·새로고침·
소유 서버 재시작 복원과 PDF 컨트롤 부재를 포함한다. 실제 원장 조회는 읽기 전용이다.

| 최종 검증 | 결과 |
|---|---|
| Python 전체 비통합 회귀 | 4,879 passed, 4 skipped |
| Report/KISA API 집중 검사 | 83 passed |
| Node UI 회귀 | 520 passed |
| 격리 PostgreSQL Workflow | 6 passed |
| 실제 Word | 5개 DOCX, 총 15페이지, 입력 셀 편집·저장·재열기 및 본문/바닥글 대조 |
| 원본 구조·문서 해시 | 원본 표·병합·머리글·로고·스타일 보존, 저장 문서와 Word 검증 SHA 일치 |
| 실제 Chromium | 실제 원장 읽기 전용 + 격리 쓰기/다운로드/재시작 복원 통과 |
| Ruff·diff | check, format, git diff --check 통과 |

변경 파일:

- `reporting/kisa_readiness.py` (신규), `kisa_observations.py` (신규).
- `reporting/kisa_contracts.py`, `kisa_mapping.py`, `kisa_narrative.py`, `kisa_docx.py`.
- `dashboard/api/kisa_forms.py`.
- `dashboard/ui/dashboard.html`, `assets/dashboard-kisa-controller.mjs`, `dashboard-workflow-controller.mjs`.
- `scripts/dev/verify_kisa_docx_word.py` (DOCX 전용 네이티브 Word 검증).
- `tests/reporting/test_kisa_forms.py`, `tests/dashboard/api/test_kisa_forms.py`,
  `tests/dashboard/ui/test_dashboard_kisa_controller.mjs`, 이전 전환 기록의 후속 링크 및 이 문서.

Word 검증 참고: [Page.EnhMetaFileBits](https://learn.microsoft.com/en-us/dotnet/api/microsoft.office.interop.word.page.enhmetafilebits?view=word-pia),
[Word 페이지·범위 정보](https://learn.microsoft.com/en-us/office/vba/api/word.wdinformation).
Word의 실제 페이지 객체와 본문·바닥글을 사용하며 PDF 엔진을 거치지 않는다.
