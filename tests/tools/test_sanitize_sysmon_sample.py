import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.sanitize_sysmon_sample import (  # noqa: E402
    build_replacements,
    count_remaining,
    restore_line,
    sanitize_line,
    stage_line,
)


def test_사용자명이_경로와_계정_양쪽에서_치환된다():
     # given - 원본 호스트명과 사용자명을 담은 Sysmon 레코드
    record = {
        "RecordId": 153,
        "EventId": 1,
        "Computer": "DESKTOP-A1B2C3",
        "EventData": {
            "Image": "C:\\Users\\khh09\\tool.exe",
            "User": "DESKTOP-A1B2C3\\khh09",
        },
    }
    replacements = build_replacements("DESKTOP-A1B2C3", "khh09")

     # when - 치환을 적용하면
    sanitized = sanitize_line(json.dumps(record), replacements)

     # then - 원본 식별자가 남지 않고 예시값으로 바뀐다
    result = json.loads(sanitized)
    assert result["Computer"] == "WIN-01"
    assert result["EventData"]["Image"] == "C:\\Users\\labuser\\tool.exe"
    assert result["EventData"]["User"] == "WIN-01\\labuser"


def test_한글_사용자명이_유니코드_이스케이프_상태에서도_치환된다():
     # given - PowerShell 5.1 이 비 ASCII 를 \uXXXX 로 이스케이프한 줄
    record = {"EventData": {"Image": "C:\\Users\\김현희\\tool.exe"}}
    line = json.dumps(record, ensure_ascii=True)
    assert "\\uae40" in line
    replacements = build_replacements("DESKTOP-A1B2C3", "김현희")

     # when - 치환을 적용하면
    sanitized = sanitize_line(line, replacements)

     # then - 한글 사용자명이 남지 않는다
    result = json.loads(sanitized)
    assert result["EventData"]["Image"] == "C:\\Users\\labuser\\tool.exe"
    assert "김현희" not in sanitized


def test_임의의_혼합_대소문자도_치환된다():
     # given - 경로와 사용자명이 혼합 대소문자로 기록된 레코드
    line = json.dumps({"EventData": {"Image": "C:\\UsErS\\kHh09\\a.exe"}})
    replacements = build_replacements("DESKTOP-A1B2C3", "khh09")

     # when - 치환을 적용하면
    sanitized = sanitize_line(line, replacements)

     # then - 대소문자와 무관하게 사용자명이 사라진다
    assert "kHh09" not in sanitized
    assert "labuser" in sanitized
    assert count_remaining([stage_line(line, replacements)], replacements) == {
        pattern.pattern: 0 for pattern, _ in replacements
    }


def test_치환값과_겹치는_사용자명도_한_번만_치환된다():
     # given - 치환 결과 labuser 에 부분 문자열로 포함되는 사용자명
    record = {"EventData": {"User": "PC\\user", "Image": "C:\\Users\\user\\a.exe"}}
    replacements = build_replacements("PC", "user")

     # when - 치환을 적용하면
    sanitized = sanitize_line(json.dumps(record), replacements)

     # then - 값이 중복 확장되지 않는다
    result = json.loads(sanitized)
    assert result["EventData"]["User"] == "WIN-01\\labuser"
    assert result["EventData"]["Image"] == "C:\\Users\\labuser\\a.exe"
    assert "lablabuser" not in sanitized


def test_치환값과_겹치는_사용자명을_누출로_세지_않는다():
     # given - 사용자명이 user 라서 결과의 labuser 와 겹치는 경우
    record = {"EventData": {"User": "PC\\user", "Image": "C:\\Users\\user\\a.exe"}}
    replacements = build_replacements("PC", "user")

     # when - sentinel 단계에서 누출을 세면
    staged = stage_line(json.dumps(record), replacements)
    counts = count_remaining([staged], replacements)

     # then - 남은 원본 식별자가 없다
    assert all(count == 0 for count in counts.values())
    assert "labuser" in restore_line(staged)


def test_사용자명이_Users_경로의_일부와_혼동되지_않는다():
     # given - 사용자명이 user 이고 경로에 Users 디렉터리가 있는 레코드
    line = json.dumps({"EventData": {"Image": "C:\\Users\\admin\\a.exe"}})
    replacements = build_replacements("PC", "user")

     # when - 치환을 적용하면
    sanitized = sanitize_line(line, replacements)

     # then - Users 디렉터리 이름은 그대로 남는다
    assert json.loads(sanitized)["EventData"]["Image"] == "C:\\Users\\admin\\a.exe"


def test_숫자와_구조는_보존된다():
     # given - 숫자·중첩 구조를 가진 레코드
    record = {"RecordId": 153, "EventId": 3, "EventData": {"DestinationPort": "443"}}
    replacements = build_replacements("DESKTOP-A1B2C3", "khh09")

     # when - 치환을 적용하면
    result = json.loads(sanitize_line(json.dumps(record), replacements))

     # then - 타입과 값이 그대로다
    assert result["RecordId"] == 153
    assert result["EventId"] == 3
    assert result["EventData"]["DestinationPort"] == "443"


def test_입력에_sentinel_이_있으면_거부한다():
     # given - sentinel 문자가 이미 포함된 줄
    line = json.dumps({"EventData": {"Image": "C:\\a\ue000b.exe"}})
    replacements = build_replacements("PC", "user")

     # when / then - 치환을 시도하면 예외가 발생한다
    try:
        stage_line(line, replacements)
    except ValueError:
        return
    raise AssertionError("ValueError 가 발생해야 한다")


def test_json_이_아니면_예외가_발생한다():
     # given - JSON 으로 파싱되지 않는 줄
    line = "{invalid json"

     # when / then - 파싱 단계에서 예외가 발생한다
    try:
        sanitize_line(line, [])
    except json.JSONDecodeError:
        return
    raise AssertionError("JSONDecodeError 가 발생해야 한다")
