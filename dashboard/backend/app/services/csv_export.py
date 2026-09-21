"""CSV 내보내기 — store.js:16-18 `toCSV()` 와 **바이트 단위로 같은** 결과를 낸다.

계약(깨면 안 됨)
  - 선두 BOM `﻿`
  - 개행 CRLF
  - 모든 셀을 큰따옴표로 감싸고, 내부 `"` 는 `""` 로 이스케이프
  - `^[=+@-]` 로 시작하는 값 앞에 작은따옴표 삽입 (Excel 수식 인젝션 방어)
  - 발생 시각은 ISO 문자열
  - 컬럼 14개, 순서 고정, 헤더 국문

서버가 CSV 를 만들면 클라이언트의 방어를 우회하므로 같은 규칙을 여기서도 적용한다
(04-backend-design.md §4.5).
"""
from __future__ import annotations

import re
from datetime import datetime, timezone

from .. import enums

# store.js:16 의 columns 배열과 동일한 순서
COLUMNS: list[tuple[str, str]] = [
    ("ID", "id"),
    ("발생 시각", "at"),
    ("시나리오", "scenario"),
    ("제목", "title"),
    ("위험도", "severity"),
    ("리전", "region"),
    ("자원", "resource"),
    ("탐지 소스", "source"),
    ("대응 방식", "mode"),
    ("상태", "status"),
    ("실행 결과", "execution"),
    ("재검증", "verification"),
    ("출발 IP", "sourceIp"),
    ("위치 상태", "geoStatus"),
]

_FORMULA = re.compile(r"^[\s]*[=+@-]|^[\t\r\n]")


def _cell(value) -> str:
    text = "" if value is None else str(value)
    text = _FORMULA.sub(lambda m: "'" + m.group(0), text, count=1)
    return '"' + text.replace('"', '""') + '"'


def _iso(ms: int) -> str:
    """JS `new Date(ms).toISOString()` 과 같은 표기 (밀리초 3자리 + 'Z')."""
    dt = datetime.fromtimestamp(ms / 1000, tz=timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def _display(event: dict, key: str):
    """API enum 을 화면 국문으로 되돌린다. CSV 는 국문이 계약이다."""
    value = event.get(key)
    if key == "at":
        return _iso(value)
    if key == "severity":
        return enums.severity_display(value)
    if key == "mode":
        return enums.mode_ko(value)
    if key == "status":
        return enums.status_ko(value)
    if key == "execution":
        return enums.execution_ko(value)
    if key == "verification":
        return enums.verification_ko(value)
    return value


def to_csv(rows: list[dict]) -> str:
    header = ",".join(_cell(label) for label, _ in COLUMNS)
    lines = [header]
    for event in rows:
        lines.append(",".join(_cell(_display(event, key)) for _, key in COLUMNS))
    return "﻿" + "\r\n".join(lines)
