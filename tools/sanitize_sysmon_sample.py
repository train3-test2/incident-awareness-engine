"""Sysmon 샘플에서 VM 고유 식별자를 치환한다.

collect_sysmon_sample.ps1 이 만든 원본 JSONL 을 samples/raw/ 에 올릴 수 있는 형태로 바꾼다.
호스트명·사용자명·사용자 프로필 경로를 문서 예시값(WIN-01, labuser)으로 치환하고,
무엇을 바꿨는지 메타데이터에 기록한다.

치환은 JSON 을 파싱한 뒤 문자열 값 단위로 수행한다. 원문 텍스트를 그대로 치환하지
않는 이유는 Windows PowerShell 5.1 의 ConvertTo-Json 이 비 ASCII 문자를 `\\uXXXX` 로
이스케이프하기 때문이다. 사용자명이 한글이면 원문에 그 글자가 그대로 나타나지 않는다.

Sysmon 원본 구조 자체는 바꾸지 않는다. event_v0 변환은 역할 3 담당이다.

사용법:
    python tools/sanitize_sysmon_sample.py <수집폴더> --out samples/raw
"""

from __future__ import annotations

import argparse
import json
from collections.abc import Iterable
from pathlib import Path
from typing import Any

 # 치환 후 사용할 값. docs/schema/event-v0.md 예시와 맞춘다
PLACEHOLDER_COMPUTER = "WIN-01"
PLACEHOLDER_USER = "labuser"

Replacement = tuple[str, str]


def build_replacements(raw_computer: str, raw_user: str) -> list[Replacement]:
    """치환 규칙을 긴 문자열 우선으로 만든다.

    파싱된 문자열 값에 적용하므로 경로 구분자는 단일 역슬래시다.
    짧은 문자열을 먼저 바꾸면 긴 문자열 안의 일부만 바뀌어 결과가 깨진다.
    """
    pairs: list[Replacement] = []

    if raw_user:
        pairs.append((f"\\Users\\{raw_user}", f"\\Users\\{PLACEHOLDER_USER}"))
        if raw_computer:
            account = f"{raw_computer}\\{raw_user}"
            pairs.append((account, f"{PLACEHOLDER_COMPUTER}\\{PLACEHOLDER_USER}"))
        pairs.append((raw_user, PLACEHOLDER_USER))

    if raw_computer:
        pairs.append((raw_computer, PLACEHOLDER_COMPUTER))

    pairs.sort(key=lambda pair: len(pair[0]), reverse=True)
    return pairs


def sanitize_text(value: str, replacements: Iterable[Replacement]) -> str:
    """문자열 하나에 치환 규칙을 적용한다.

    Windows 경로는 대소문자를 가리지 않으므로 소문자·대문자 변형도 함께 처리한다.
    한글처럼 대소문자가 없는 문자는 변형이 원문과 같아 중복 적용해도 결과가 같다.
    """
    result = value
    for source, target in replacements:
        for variant in (source, source.lower(), source.upper()):
            result = result.replace(variant, target)
    return result


def sanitize_object(node: Any, replacements: Iterable[Replacement]) -> Any:
    """JSON 구조를 따라가며 문자열 값만 치환한다.

    Key 는 Sysmon 이 정한 필드명이므로 건드리지 않는다.
    """
    if isinstance(node, str):
        return sanitize_text(node, replacements)
    if isinstance(node, dict):
        return {key: sanitize_object(value, replacements) for key, value in node.items()}
    if isinstance(node, list):
        return [sanitize_object(item, replacements) for item in node]
    return node


def sanitize_line(line: str, replacements: Iterable[Replacement]) -> str:
    """JSONL 한 줄을 파싱해 치환한 뒤 다시 직렬화한다."""
    parsed = json.loads(line)
    sanitized = sanitize_object(parsed, replacements)
    return json.dumps(sanitized, ensure_ascii=False, separators=(",", ":"))


def count_remaining(lines: Iterable[str], tokens: Iterable[str]) -> dict[str, int]:
    """치환이 끝난 뒤에도 원본 토큰이 남아 있는지 센다."""
    joined = "\n".join(lines)
    lowered = joined.lower()
    counts: dict[str, int] = {}
    for token in tokens:
        if not token:
            continue
        counts[token] = lowered.count(token.lower())
    return counts


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
    raw_computer = meta.get("raw_computer", "")
    raw_user = meta.get("raw_user", "")

    replacements = build_replacements(raw_computer, raw_user)
    source_lines = jsonl_path.read_text(encoding="utf-8").splitlines()
    sanitized = [sanitize_line(line, replacements) for line in source_lines if line.strip()]

    remaining = count_remaining(sanitized, [raw_computer, raw_user])
    leaked = {token: count for token, count in remaining.items() if count > 0}
    if leaked:
        print(f"[!] 치환되지 않은 식별자가 남아 있다: {leaked}")
        return 1

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
