import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from tools.sanitize_sysmon_sample import (
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
        "Computer": "DESKTOP-TEST01",
        "EventData": {
            "Image": "C:\\Users\\testuser\\tool.exe",
            "User": "DESKTOP-TEST01\\testuser",
        },
    }
    replacements = build_replacements("DESKTOP-TEST01", "testuser")

    # when - 치환을 적용하면
    sanitized = sanitize_line(json.dumps(record), replacements)

    # then - 원본 식별자가 남지 않고 예시값으로 바뀐다
    result = json.loads(sanitized)
    assert result["Computer"] == "WIN-01"
    assert result["EventData"]["Image"] == "C:\\Users\\labuser\\tool.exe"
    assert result["EventData"]["User"] == "WIN-01\\labuser"


def test_한글_사용자명이_유니코드_이스케이프_상태에서도_치환된다():
    # given - PowerShell 5.1 이 비 ASCII 를 \uXXXX 로 이스케이프한 줄
    record = {"EventData": {"Image": "C:\\Users\\홍길동\\tool.exe"}}
    line = json.dumps(record, ensure_ascii=True)
    assert "\\ud64d" in line
    replacements = build_replacements("DESKTOP-TEST01", "홍길동")

    # when - 치환을 적용하면
    sanitized = sanitize_line(line, replacements)

    # then - 한글 사용자명이 남지 않는다
    result = json.loads(sanitized)
    assert result["EventData"]["Image"] == "C:\\Users\\labuser\\tool.exe"
    assert "홍길동" not in sanitized


def test_임의의_혼합_대소문자도_치환된다():
    # given - 경로와 사용자명이 혼합 대소문자로 기록된 레코드
    line = json.dumps({"EventData": {"Image": "C:\\UsErS\\tEsTuSeR\\a.exe"}})
    replacements = build_replacements("DESKTOP-TEST01", "testuser")

    # when - 치환을 적용하면
    sanitized = sanitize_line(line, replacements)

    # then - 대소문자와 무관하게 사용자명이 사라진다
    assert "tEsTuSeR" not in sanitized
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


def test_한글_사용자명이_독립_토큰일_때만_치환된다():
    # given - 한글 사용자명이 경로 구분자로 둘러싸인 경우와 다른 글자에 붙은 경우
    record = {
        "EventData": {
            "Image": "C:\\Users\\홍길동\\a.exe",
            "CommandLine": "abc홍길동def",
        }
    }
    replacements = build_replacements("PC", "홍길동")

    # when - 치환을 적용하면
    result = json.loads(sanitize_line(json.dumps(record), replacements))

    # then - 독립 토큰만 바뀌고 다른 글자에 붙은 것은 남는다
    assert result["EventData"]["Image"] == "C:\\Users\\labuser\\a.exe"
    assert result["EventData"]["CommandLine"] == "abc홍길동def"


def test_호스트명이_FQDN_형태에서도_치환된다():
    # given - Sysmon NetworkConnect 가 기록하는 <host>.localdomain 형태
    record = {
        "Computer": "DESKTOP-TEST01",
        "EventData": {
            "SourceHostname": "DESKTOP-TEST01.localdomain",
            "DestinationHostname": "DESKTOP-TEST01.localdomain",
        },
    }
    replacements = build_replacements("DESKTOP-TEST01", "testuser")

    # when - 치환을 적용하면
    sanitized = sanitize_line(json.dumps(record), replacements)

    # then - 뒤에 붙은 도메인 때문에 막히지 않는다
    result = json.loads(sanitized)
    assert result["Computer"] == "WIN-01"
    assert result["EventData"]["SourceHostname"] == "WIN-01.localdomain"
    assert "DESKTOP-TEST01" not in sanitized


def test_짧은_토큰이_PowerShell_옵션_안에서_치환되지_않는다():
    # given - 사용자명이 옵션 문자열에 부분 일치할 수 있는 짧은 토큰인 경우
    record = {
        "EventData": {
            "CommandLine": "powershell.exe -NoProfile -Command x",
            "User": "PC\\pro",
        }
    }
    replacements = build_replacements("PC", "pro")

    # when - 치환을 적용하면
    result = json.loads(sanitize_line(json.dumps(record), replacements))

    # then - 옵션은 그대로 두고 계정만 바뀐다
    assert result["EventData"]["CommandLine"] == "powershell.exe -NoProfile -Command x"
    assert result["EventData"]["User"] == "WIN-01\\labuser"


def test_중간_경로에_Users_가_있어도_치환된다():
    # given - 사용자 프로필이 최상위가 아닌 경로
    line = json.dumps({"EventData": {"Image": "D:\\Data\\Users\\testuser\\a.exe"}})
    replacements = build_replacements("PC", "testuser")

    # when - 치환을 적용하면
    sanitized = sanitize_line(line, replacements)

    # then - 앞 경계 때문에 막히지 않는다
    assert json.loads(sanitized)["EventData"]["Image"] == "D:\\Data\\Users\\labuser\\a.exe"


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
    replacements = build_replacements("DESKTOP-TEST01", "testuser")

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
    with pytest.raises(ValueError):
        stage_line(line, replacements)


def test_json_이_아니면_예외가_발생한다():
    # given - JSON 으로 파싱되지 않는 줄
    line = "{invalid json"

    # when / then - 파싱 단계에서 예외가 발생한다
    with pytest.raises(json.JSONDecodeError):
        sanitize_line(line, [])
