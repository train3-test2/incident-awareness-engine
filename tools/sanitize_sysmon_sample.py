"""Sysmon 샘플에서 VM 고유 식별자를 치환한다.

collect_sysmon_sample.ps1 이 만든 원본 JSONL 을 samples/raw/ 에 올릴 수 있는 형태로 바꾼다.
호스트명·사용자명·사용자 프로필 경로를 문서 예시값(WIN-01, labuser)으로 치환하고,
무엇을 바꿨는지 메타데이터에 기록한다.

치환은 세 단계로 나눈다.

    1단계  원본 식별자 -> 충돌하지 않는 sentinel
    2단계  누출 검사
    3단계  sentinel -> 최종 예시값

바로 최종값으로 치환하면 두 가지 문제가 생긴다. 치환 규칙이 이미 치환된 결과에 다시 걸려
값이 중복 확장되고(`user` -> `labuser` -> `lablabuser`), 최종값이 원본 토큰을 부분 문자열로
포함할 때(`labuser` 안의 `user`) 정상 결과를 누출로 오판한다.

치환은 JSON 을 파싱한 뒤 문자열 값 단위로 수행한다. 원문 텍스트를 그대로 치환하지 않는
이유는 Windows PowerShell 5.1 의 ConvertTo-Json 이 비 ASCII 문자를 `\\uXXXX` 로 이스케이프할
수 있기 때문이다. 사용자명이 한글이면 원문에 그 글자가 그대로 나타나지 않는다.

Sysmon 원본 구조 자체는 바꾸지 않는다. event_v0 변환은 역할 3 담당이다.

사용법:
    python tools/sanitize_sysmon_sample.py <수집폴더> --out samples/raw
"""

from __future__ import annotations

import argparse
import json
import re
from collections.abc import Iterable, Iterator
from pathlib import Path
from typing import Any

 # 치환 후 사용할 값. docs/schema/event-v0.md 예시와 맞춘다
PLACEHOLDER_COMPUTER = "WIN-01"
PLACEHOLDER_USER = "labuser"

 # 중간 단계 표식. Private Use Area 문자라 실제 telemetry 와 충돌하지 않는다
SENTINEL_COMPUTER = "\ue000"
SENTINEL_USER = "\ue001"

SENTINELS = {
    SENTINEL_COMPUTER: PLACEHOLDER_COMPUTER,
    SENTINEL_USER: PLACEHOLDER_USER,
}

Replacement = tuple[re.Pattern[str], str]


 # 경계 판정 문자. `\w` 는 유니코드를 포함하므로 한글 사용자명에도 경계가 걸린다
WORD_CHAR = re.compile(r"\w")


def _boundaried(token: str) -> str:
    """토큰 양끝이 단어 문자면 경계 조건을 붙인다.

    경계가 없으면 짧은 토큰이 엉뚱한 곳에 걸린다. 사용자명이 `user` 면
    `C:\\Users\\` 의 `User` 에, 한글 사용자명이면 다른 한글 문자열 안에도 걸린다.

    경계는 토큰 끝이 단어 문자일 때만 붙인다. `\\Users\\<name>` 처럼 구분자로
    시작하는 토큰에 앞 경계를 붙이면 `D:\\Data\\Users\\<name>` 같은 경로에서
    치환이 막힌다.

    경계 문자에 `.` 과 `-` 는 넣지 않는다. Sysmon NetworkConnect 의
    `SourceHostname` 은 `<host>.localdomain` 형태라, `.` 을 경계로 보면 호스트명이
    치환되지 않고 그대로 남는다.

    한계: 단어 문자로 이어 붙은 형태(`<name>_backup.zip`)는 치환하지 않는다.
    누출 검사도 같은 규칙을 쓰므로 검사와 치환의 판정이 어긋나지는 않는다.
    """
    prefix = r"(?<!\w)" if WORD_CHAR.match(token[:1]) else ""
    suffix = r"(?!\w)" if WORD_CHAR.match(token[-1:]) else ""
    return prefix + re.escape(token) + suffix


def build_replacements(raw_computer: str, raw_user: str) -> list[Replacement]:
    """치환 규칙을 긴 문자열 우선으로 만든다.

    파싱된 문자열 값에 적용하므로 경로 구분자는 단일 역슬래시다.
    짧은 문자열을 먼저 바꾸면 긴 문자열 안의 일부만 바뀌어 결과가 깨진다.
    Windows 경로는 대소문자를 가리지 않으므로 대소문자를 무시하고 비교한다.
    """
    pairs: list[tuple[str, str]] = []

    if raw_user:
        pairs.append((f"\\Users\\{raw_user}", f"\\Users\\{SENTINEL_USER}"))
        if raw_computer:
            pairs.append((f"{raw_computer}\\{raw_user}", f"{SENTINEL_COMPUTER}\\{SENTINEL_USER}"))
        pairs.append((raw_user, SENTINEL_USER))

    if raw_computer:
        pairs.append((raw_computer, SENTINEL_COMPUTER))

    pairs.sort(key=lambda pair: len(pair[0]), reverse=True)
    return [(re.compile(_boundaried(src), re.IGNORECASE), dst) for src, dst in pairs]


def stage_text(value: str, replacements: Iterable[Replacement]) -> str:
    """문자열 하나를 sentinel 단계까지 치환한다."""
    result = value
    for pattern, target in replacements:
         # 치환값에 역슬래시가 있어 re.sub 의 escape 해석을 피한다
        result = pattern.sub(lambda _match, value=target: value, result)
    return result


def stage_object(node: Any, replacements: Iterable[Replacement]) -> Any:
    """JSON 구조를 따라가며 문자열 값만 치환한다.

    Key 는 Sysmon 이 정한 필드명이므로 건드리지 않는다.
    """
    if isinstance(node, str):
        return stage_text(node, replacements)
    if isinstance(node, dict):
        return {key: stage_object(value, replacements) for key, value in node.items()}
    if isinstance(node, list):
        return [stage_object(item, replacements) for item in node]
    return node


def iter_string_values(node: Any) -> Iterator[str]:
    """JSON 구조에서 문자열 값만 순회한다.

    Key 는 Sysmon 이 정한 필드명이라 치환 대상이 아니므로 검사에서도 제외한다.
    """
    if isinstance(node, str):
        yield node
    elif isinstance(node, dict):
        for value in node.values():
            yield from iter_string_values(value)
    elif isinstance(node, list):
        for item in node:
            yield from iter_string_values(item)


def stage_line(line: str, replacements: Iterable[Replacement]) -> str:
    """JSONL 한 줄을 파싱해 sentinel 단계까지 치환한 뒤 다시 직렬화한다."""
    parsed = json.loads(line)

     # 이스케이프 표기와 무관하게 판정하려면 파싱한 값에서 확인해야 한다
    for value in iter_string_values(parsed):
        for sentinel in SENTINELS:
            if sentinel in value:
                raise ValueError("입력에 sentinel 문자가 이미 존재한다.")

    staged = stage_object(parsed, replacements)
    return json.dumps(staged, ensure_ascii=False, separators=(",", ":"))


def restore_line(staged: str) -> str:
    """sentinel 을 최종 예시값으로 되돌린다."""
    result = staged
    for sentinel, placeholder in SENTINELS.items():
        result = result.replace(sentinel, placeholder)
    return result


def sanitize_line(line: str, replacements: Iterable[Replacement]) -> str:
    """JSONL 한 줄을 최종 형태까지 치환한다."""
    return restore_line(stage_line(line, replacements))


def count_remaining(lines: Iterable[str], replacements: Iterable[Replacement]) -> dict[str, int]:
    """치환이 끝난 뒤에도 원본 식별자가 남아 있는지 센다.

    sentinel 단계의 줄을 대상으로 호출한다. 최종값으로 되돌린 뒤에 세면
    `labuser` 안의 `user` 처럼 치환 결과가 원본 토큰을 포함해 오판한다.

    검사 범위는 문자열 값으로 한정한다. 직렬화된 원문을 그대로 세면 `User` 같은
    Sysmon 필드명이 사용자명과 일치해 오판한다.
    """
    values: list[str] = []
    for line in lines:
        values.extend(iter_string_values(json.loads(line)))

    joined = "\n".join(values)
    return {pattern.pattern: len(pattern.findall(joined)) for pattern, _ in replacements}


def main() -> int:
    parser = argparse.ArgumentParser(description="Sysmon 샘플 식별자 치환")
    parser.add_argument("source", type=Path, help="collect_sysmon_sample.ps1 결과 폴더")
    parser.add_argument("--out", type=Path, default=Path("samples/raw"), help="출력 폴더")
    args = parser.parse_args()

    jsonl_path = args.source / "sysmon-0001.jsonl"
    meta_path = args.source / "collection-meta.json"

    for path in (jsonl_path, meta_path):
        if not path.exists():
            print(f"[!] 파일이 없다: {path}")
            return 1

    meta = json.loads(meta_path.read_text(encoding="utf-8"))

     # 수집기가 필수 검사에 실패한 Run 은 샘플로 올리지 않는다
    failures = meta.get("validation_failures") or []
    if failures:
        print(f"[!] 수집 단계 검사에 실패한 Run 이다: {', '.join(failures)}")
        print("[!] 원인을 해결하고 다시 수집할 것. 샘플을 만들지 않는다.")
        return 1

    raw_computer = meta.get("raw_computer", "")
    raw_user = meta.get("raw_user", "")

    replacements = build_replacements(raw_computer, raw_user)
    source_lines = jsonl_path.read_text(encoding="utf-8").splitlines()
    staged = [stage_line(line, replacements) for line in source_lines if line.strip()]

     # 누출 검사는 sentinel 을 되돌리기 전에 수행한다
    remaining = count_remaining(staged, replacements)
    leaked = {token: count for token, count in remaining.items() if count > 0}
    if leaked:
        print(f"[!] 치환되지 않은 식별자가 남아 있다: {leaked}")
        return 1

    sanitized = [restore_line(line) for line in staged]

    args.out.mkdir(parents=True, exist_ok=True)
    out_jsonl = args.out / "sysmon-0001.jsonl"
    out_jsonl.write_text(
        "\n".join(sanitized) + "\n",
        encoding="utf-8",
        newline="\n",
    )

     # 원본 호스트명·사용자명은 기록하지 않는다. 치환했다는 사실만 남긴다
    published_meta = {
        "purpose": meta.get("purpose", "schema-development-sample"),
        "collected_at": meta.get("collected_at"),
        "sysmon_config_version": meta.get("sysmon_config_version"),
        "sysmon_config_sha256": meta.get("sysmon_config_sha256"),
        "sysmon_active_config_sha256": meta.get("sysmon_active_config_sha256"),
        "sysmon_version": meta.get("sysmon_version"),
        "os_caption": meta.get("os_caption"),
        "os_version": meta.get("os_version"),
        "event_counts": meta.get("event_counts"),
        "external_connection": meta.get("external_connection"),
        "evidence_condition_hits": meta.get("evidence_condition_hits"),
        "sanitized": {
            "computer": PLACEHOLDER_COMPUTER,
            "user": PLACEHOLDER_USER,
            "rule": "원본 호스트명과 사용자명을 문서 예시값으로 치환",
        },
    }

    out_meta = args.out / "sysmon-sample-meta.json"
    out_meta.write_text(
        json.dumps(published_meta, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )

    print(f"[+] {len(sanitized)} 건 저장: {out_jsonl}")
    print(f"[+] 메타데이터 저장: {out_meta}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
