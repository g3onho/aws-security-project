"""이벤트 필터 — store.js:6 `selectEvents()` 의 서버 측 재현.

프론트가 클라이언트에서 하던 필터를 서버가 그대로 해야 화면 동작이 바뀌지 않는다.
검색 대상 필드는 **정확히 5개**(id, title, resource, scenario, sourceIp)이고
정렬은 **발생 시각 내림차순 고정**이다.
"""
from __future__ import annotations

import base64
import json

from ..config import Config

SEARCH_FIELDS = ("id", "title", "resource", "scenario", "sourceIp")


def apply_filters(rows: list[dict], q: dict) -> list[dict]:
    region = q.get("region") or "all"
    ignore_region = bool(q.get("ignoreRegion"))
    environment = q.get("environment")
    start, end = q.get("from"), q.get("to")
    severity = q.get("severity")
    status = q.get("status")
    source = q.get("source")
    scenario = q.get("scenario")
    needle = (q.get("q") or "").lower()

    out = []
    for e in rows:
        if not (ignore_region or region == "all" or e["region"] == region):
            continue
        if environment and e["environment"] != environment:
            continue
        if start is not None and e["at"] < start:
            continue
        if end is not None and e["at"] > end:
            continue
        if severity and e["severity"] != severity:
            continue
        if status and e["status"] != status:
            continue
        if source and e["source"] != source:
            continue
        if scenario and e["scenario"] != scenario:
            continue
        if needle:
            hay = " ".join(str(e.get(f) or "") for f in SEARCH_FIELDS).lower()
            if needle not in hay:
                continue
        out.append(e)

    # store.js:6 은 `b.at - a.at` 만 쓴다. JS sort 는 안정 정렬이라 동점은 원래 순서
    # (리전 순 = id 오름차순)를 유지한다. 커서 페이지네이션이 성립하려면 정렬이
    # 전순서여야 하므로 동점 타이브레이커를 **id 오름차순**으로 명시한다.
    # 이러면 화면 행 순서는 기존과 같으면서 커서 비교가 일관된다.
    out.sort(key=lambda e: (-e["at"], e["id"]))
    return out


def paginate(rows: list[dict], q: dict) -> dict:
    """커서 페이지네이션.

    커서는 (at, id) 복합키를 base64 로 감싼 것이다. 정렬이 at 내림차순 고정이므로
    offset 이 아니라 마지막 항목의 키를 기준으로 잘라 중복·누락을 막는다.
    """
    limit = q.get("limit") or Config.DEFAULT_LIMIT
    limit = max(1, min(int(limit), Config.MAX_LIMIT))
    total = len(rows)

    cursor = q.get("cursor")
    if cursor:
        try:
            mark = json.loads(base64.urlsafe_b64decode(cursor.encode()).decode())
            # 정렬 키 (-at, id) 기준으로 마지막 항목보다 "뒤"에 오는 것만 남긴다.
            # at 만 비교하면 같은 시각 이벤트가 매 페이지마다 다시 나온다.
            key = (-mark["at"], mark["id"])
            rows = [e for e in rows if (-e["at"], e["id"]) > key]
        except Exception:
            from ..api.errors import ApiProblem
            raise ApiProblem(400,'페이지 커서가 올바르지 않습니다.',code='INVALID_PARAMETER')

    page = rows[:limit]
    next_cursor = None
    if len(rows) > limit and page:
        last = page[-1]
        next_cursor = base64.urlsafe_b64encode(
            json.dumps({"at": last["at"], "id": last["id"]}).encode()
        ).decode()

    return {"items": page, "nextCursor": next_cursor, "total": total, "truncated": False}
