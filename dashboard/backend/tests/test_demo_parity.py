"""데모 어댑터가 data.js 와 같은 데이터를 내는지 대조한다.

Node 로 static/js/data.js 를 실행해 원본을 덤프하고, demo.py 포팅 결과와
이벤트 단위로 비교한다. data.js 를 고치면 이 테스트가 먼저 깨진다.

Node 가 없으면 skip 한다(윈도우 PC 에서 pytest 만 돌릴 수 있게).
"""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from app import enums
from app.adapters import demo as demo_mod

ROOT = Path(__file__).resolve().parents[1]   # dashboard/backend
DUMP = Path(__file__).with_name("dump_demo.mjs")


@pytest.fixture(scope="module")
def js_dump():
    if not shutil.which("node"):
        pytest.skip("node 가 없어 data.js 대조를 건너뜁니다")
    proc = subprocess.run(
        ["node", str(DUMP)], cwd=ROOT, capture_output=True, text=True, encoding="utf-8", timeout=60,
    )
    if proc.returncode != 0:
        pytest.fail(f"dump_demo.mjs 실패: {proc.stderr[:500]}")
    return json.loads(proc.stdout)


def test_demo_now_matches(js_dump):
    assert demo_mod.DEMO_NOW == js_dump["DEMO_NOW"]


def test_event_count_matches(js_dump):
    ours = demo_mod._build_events()
    assert len(ours) == js_dump["count"], "이벤트 개수가 data.js 와 다릅니다"


def test_every_event_matches(js_dump):
    ours = {e["id"]: e for e in demo_mod._build_events()}
    theirs = {e["id"]: e for e in js_dump["events"]}
    assert set(ours) == set(theirs), "이벤트 ID 집합이 다릅니다"

    mismatches = []
    for event_id, js in theirs.items():
        py = ours[event_id]
        checks = {
            "scenario": (py["scenario"], js["scenario"]),
            "title": (py["title"], js["title"]),
            "severity": (py["severity"], enums.DISPLAY_TO_SEVERITY[js["severity"]]),
            "source": (py["source"], js["source"]),
            "mode": (py["mode"], enums.KO_TO_MODE[js["mode"]]),
            "region": (py["region"], js["region"]),
            "environment": (py["environment"], js["environment"]),
            "resource": (py["resource"], js["resource"]),
            "at": (py["at"], js["at"]),
            "status": (py["status"], enums.KO_TO_STATUS[js["status"]]),
            "execution": (py["execution"], enums.EXECUTION_TO_KO and
                          {v: k for k, v in enums.EXECUTION_TO_KO.items()}[js["execution"]]),
            "verification": (py["verification"],
                             {v: k for k, v in enums.VERIFICATION_TO_KO.items()}[js["verification"]]),
            "criterion": (py["criterion"], js["criterion"]),
            "unit": (py["unit"], js["unit"]),
            "beforeAt": (py["beforeAt"], js["beforeAt"]),
            "afterAt": (py["afterAt"], js["afterAt"]),
            "afterValue": (py["afterValue"], js["afterValue"]),
            "evidence": (py["evidence"], js["evidence"]),
            "recommendation": (py["recommendation"], js["recommendation"]),
            "sourceIp": (py["sourceIp"], js["sourceIp"]),
            "geoStatus": (py["geoStatus"], js["geoStatus"]),
            "before.value": (py["before"]["value"], js["before"]),
        }
        for field, (got, want) in checks.items():
            if got != want:
                mismatches.append(f"{event_id}.{field}: python={got!r} js={want!r}")

        # sourceLocation
        if (py["sourceLocation"] is None) != (js["sourceLocation"] is None):
            mismatches.append(f"{event_id}.sourceLocation: 존재 여부 불일치")
        elif py["sourceLocation"]:
            for key in ("city", "lon", "lat", "provenance", "actorId", "country"):
                if py["sourceLocation"][key] != js["sourceLocation"][key]:
                    mismatches.append(
                        f"{event_id}.sourceLocation.{key}: "
                        f"python={py['sourceLocation'][key]!r} js={js['sourceLocation'][key]!r}"
                    )

        # history — 시각과 문구
        if len(py["history"]) != len(js["history"]):
            mismatches.append(f"{event_id}.history: 길이 {len(py['history'])} != {len(js['history'])}")
        else:
            for index, (a, b) in enumerate(zip(py["history"], js["history"])):
                if a["at"] != b["at"] or a["text"] != b["text"]:
                    mismatches.append(f"{event_id}.history[{index}]: {a} != {b}")

    assert not mismatches, "data.js 와 어긋난 필드:\n" + "\n".join(mismatches[:40])


def test_metrics_match(js_dump):
    for key, want in js_dump["metrics"].items():
        region, hours, offset, env = key.split("|")
        got = demo_mod.metrics_for(region, float(hours), float(offset), env)
        if want is None:
            assert got["resource"] is None, f"{key}: 원본은 null 인데 자원이 있습니다"
            continue
        assert got["resource"] == want["resource"], key
        assert got["cpu"] == want["cpu"], f"{key} cpu"
        assert got["memory"] == want["memory"], f"{key} memory"
        assert got["at"] == want["at"], f"{key} at"
        assert len(got["points"]) == len(want["points"]), f"{key} points 길이"
        for index, (a, b) in enumerate(zip(got["points"], want["points"])):
            # data.js 는 `DEMO_NOW - offset*3600000` 을 float 그대로 둔다(예: ...272.7273).
            # API 는 at 을 정수 ms 로 규정했으므로(03-api-spec.yaml) 여기서만 1ms 오차를
            # 허용한다. 차트 x축에서 1ms 미만은 의미가 없다.
            assert abs(a["at"] - b["at"]) < 1, f"{key} points[{index}] at"
            assert (a["cpu"], a["memory"]) == (b["cpu"], b["memory"]), \
                f"{key} points[{index}] 값"
