import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.sanitize_sysmon_sample import (  # noqa: E402
    build_replacements,
    count_remaining,
    sanitize_line,
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
    assert "\\ud558" in line or "\\uae40" in line
    replacements = build_replacements("DESKTOP-A1B2C3", "김현희")

     # when - 치환을 적용하면
    sanitized = sanitize_line(line, replacements)

     # then - 한글 사용자명이 남지 않는다
    result = json.loads(sanitized)
    assert result["EventData"]["Image"] == "C:\\Users\\labuser\\tool.exe"
    assert "김현희" not in sanitized


def test_대소문자가_다른_경로도_치환된다():
     # given - 경로가 대문자로 기록된 레코드
    line = json.dumps({"EventData": {"Image": "C:\\USERS\\KHH09\\a.exe"}})
    replacements = build_replacements("DESKTOP-A1B2C3", "khh09")

     # when - 치환을 적용하면
    sanitized = sanitize_line(line, replacements)

     # then - 사용자명이 남지 않는다
    assert "KHH09" not in sanitized
    assert "labuser" in sanitized


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


def test_치환_후_남은_식별자를_센다():
     # given - 치환이 끝난 줄 목록
    lines = [json.dumps({"EventData": {"Image": "C:\\Users\\labuser\\a.exe"}})]

     # when - 원본 토큰이 남았는지 세면
    counts = count_remaining(lines, ["DESKTOP-A1B2C3", "khh09"])

     # then - 모두 0 이다
    assert counts == {"DESKTOP-A1B2C3": 0, "khh09": 0}


def test_json_이_아니면_예외가_발생한다():
     # given - JSON 으로 파싱되지 않는 줄
    line = "{invalid json"

     # when / then - 파싱 단계에서 예외가 발생한다
    try:
        sanitize_line(line, [])
    except json.JSONDecodeError:
        return
    raise AssertionError("JSONDecodeError 가 발생해야 한다")
