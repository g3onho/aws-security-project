"""CSV 내보내기가 store.js:16-18 의 toCSV 와 바이트 단위로 같은지 대조한다.

CSV 는 증적 문서에 붙는 산출물이고, 서버가 만들면 클라이언트 측 수식 인젝션 방어를
우회하므로(04-backend-design.md §4.5) 규칙이 어긋나면 안 된다.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from app import enums
from app.adapters import demo as demo_mod
from app.services.csv_export import to_csv, _cell, _iso

ROOT = Path(__file__).resolve().parents[1]   # dashboard/backend
DUMP = Path(__file__).with_name("dump_csv.mjs")


@pytest.fixture(scope="module")
def js_csv():
    if not shutil.which("node"):
        pytest.skip("node 가 없어 toCSV 대조를 건너뜁니다")
    proc = subprocess.run(
        ["node", str(DUMP)], cwd=ROOT, capture_output=True, text=True, encoding="utf-8", timeout=60,
    )
    if proc.returncode != 0:
        pytest.fail(f"dump_csv.mjs 실패: {proc.stderr[:500]}")
    return json.loads(proc.stdout)


def test_matches_store_js(js_csv):
    by_id = {e["id"]: e for e in demo_mod._build_events()}
    rows = [by_id[i] for i in js_csv["ids"] if i in by_id]

    hostile_js = js_csv["hostile"]
    hostile = dict(by_id[js_csv["ids"][0]])
    hostile.update(
        id=hostile_js["id"],
        title=hostile_js["title"],
        resource=hostile_js["resource"],
        sourceIp=hostile_js["sourceIp"],
    )
    rows.append(hostile)

    assert to_csv(rows) == js_csv["csv"], "toCSV 와 결과가 다릅니다"


def test_bom_and_crlf():
    text = to_csv([])
    assert text.startswith("﻿"), "BOM 이 없습니다"
    assert "\r\n" not in text, "헤더만 있을 때는 개행이 없어야 합니다"

    rows = demo_mod._build_events()[:2]
    text = to_csv(rows)
    assert text.count("\r\n") == len(rows), "데이터 행마다 CRLF 하나"


@pytest.mark.parametrize("raw,expected", [
    ("=1+1", "\"'=1+1\""),
    ("+1", "\"'+1\""),
    ("@SUM(1)", "\"'@SUM(1)\""),
    ("-1", "\"'-1\""),
    ('he said "hi"', '"he said ""hi"""'),
    ("", '""'),
    (None, '""'),
    ("normal", '"normal"'),
])
def test_formula_injection_and_quoting(raw, expected):
    assert _cell(raw) == expected


def test_iso_has_milliseconds():
    # JS 의 toISOString() 과 같은 표기여야 한다.
    assert _iso(1789711200000) == "2026-09-18T06:00:00.000Z"


def test_header_columns_are_korean_and_ordered():
    header = to_csv([]).lstrip("﻿")
    assert header.split(",")[0] == '"ID"'
    assert '"위치 상태"' in header
    assert header.count(",") == 13, "컬럼 14개"


def test_status_is_rendered_in_korean():
    rows = [e for e in demo_mod._build_events() if e["status"] == "PENDING_APPROVAL"][:1]
    assert rows, "승인 대기 이벤트가 있어야 합니다"
    assert enums.status_ko("PENDING_APPROVAL") in to_csv(rows)
    assert "PENDING_APPROVAL" not in to_csv(rows), "CSV 에 영문 enum 이 새면 안 됩니다"
