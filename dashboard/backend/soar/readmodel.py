"""Projection helpers for observed events; no bundled operational data."""
from __future__ import annotations

import base64
import csv
import hashlib
import io
import json
from datetime import datetime, timezone

from .errors import Problem

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
STATUS_LABELS = {
    "NEW": "신규", "PENDING_APPROVAL": "승인 대기", "APPROVED": "승인됨",
    "EXECUTING": "조치 실행 중", "PENDING_VERIFICATION": "재검증 대기",
    "VERIFYING": "재검증 중", "RESOLVED": "해결",
    "VERIFICATION_FAILED": "재검증 실패", "EXECUTION_FAILED": "실행 실패",
}
EXECUTION_LABELS = {"NOT_RUN": "미실행", "RUNNING": "실행 중", "SUCCEEDED": "성공", "FAILED": "실패"}
VERIFICATION_LABELS = {"NOT_RUN": "미실행", "CHECKING": "검사 중", "PASSED": "통과", "FAILED": "실패"}




def filter_events(events: list[dict], q: dict) -> list[dict]:
    """Half-open [from, to) bounds; newest first, then ID for stable pages."""
    result = []
    needle = (q.get("q") or "").casefold()
    for event in events:
        if not q.get("ignoreRegion") and q.get("region") not in (None, "", "all", event["region"]):
            continue
        if any(q.get(key) and q[key] != event.get(key)
               for key in ("resource", "environment", "severity", "status", "source", "scenario")):
            continue
        if q.get("from") is not None and event["at"] < q["from"]:
            continue
        if q.get("to") is not None and event["at"] >= q["to"]:
            continue
        searchable = " ".join(str(event.get(key) or "") for key in ("id", "title", "resource", "scenario", "sourceIp"))
        if needle and needle not in searchable.casefold():
            continue
        result.append(event)
    return sorted(result, key=lambda event: (-event["at"], event["id"]))


def _view(events: list[dict], q: dict) -> list[dict]:
    if q.get("view") == "vulnerabilities":
        return [event for event in events if event["source"] in {"Inspector", "Trivy"}]
    if q.get("view") == "responses":
        return [event for event in events if len(event.get("history", [])) > 1
                or event["status"] == "PENDING_APPROVAL"]
    return events


def paginate(events: list[dict], q: dict) -> dict:
    rows = _view(filter_events(events, q), q)
    total = len(rows)
    if q.get("cursor"):
        try:
            mark = json.loads(base64.urlsafe_b64decode(q["cursor"]).decode("utf-8"))
            if not isinstance(mark, dict) or type(mark.get("at")) is not int or not isinstance(mark.get("id"), str):
                raise ValueError("invalid cursor")
            rows = [row for row in rows if (-row["at"], row["id"]) > (-mark["at"], mark["id"])]
        except (ValueError, TypeError, UnicodeError, KeyError) as error:
            raise Problem(400, "페이지 커서가 올바르지 않습니다.", code="INVALID_PARAMETER") from error
    limit = q.get("limit", 100)
    page = rows[:limit]
    cursor = None
    if len(rows) > limit and page:
        last = page[-1]
        cursor = base64.urlsafe_b64encode(json.dumps({"at": last["at"], "id": last["id"]}).encode()).decode()
    return {"items": page, "total": total, "nextCursor": cursor, "truncated": False}


def _counts(events: list[dict], field: str) -> dict:
    result = {}
    for event in events:
        result[event[field]] = result.get(event[field], 0) + 1
    return result


def snapshot(events: list[dict], q: dict) -> dict:
    rows = _view(filter_events(events, q), q)
    regional = filter_events(events, {**q, "ignoreRegion": True})
    resolved = sum(row["verification"] == "PASSED" for row in rows)
    encoded = json.dumps(rows, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return {
        "items": rows, "regionalItems": regional,
        "summary": {"total": len(rows), "resolved": resolved,
                    "resolutionRate": round(resolved / len(rows) * 100, 1) if rows else None,
                    "regions": _counts(regional, "region"), "sources": _counts(rows, "source"),
                    "severity": _counts(rows, "severity")},
        "snapshot": hashlib.sha256(encoded.encode()).hexdigest()[:20],
        "asOf": q.get("to"), "collectedAt": q.get("collectedAt", q.get("to")), "mode": "live",
    }








def evidence(event: dict) -> dict:
    """Evidence fields retain their recorded source."""
    fields = [
        ("자산명 / 자산 ID", event["resource"]),
        ("점검 항목 · 기준 ID", f"{event['scenario']} · {event['criterionVersion']}"),
        ("현재 설정", (event.get("before") or {}).get("value")),
        ("점검 명령 · 화면 경로", event.get("verificationCommand")),
        ("원본 점검 결과", event.get("evidence")),
        ("취약 여부 / 위험도", f"{'양호' if event['verification'] == 'PASSED' else '취약'} · {event['severity']}"),
        ("판정 근거와 영향", event.get("criterion")),
        ("개선 방법 · 담당자", f"{event.get('recommendation', '')} · {event.get('approver') or '미승인'}"),
        ("Terraform·설정 변경", (event.get("plan") or {}).get("change")),
        ("Plan·Apply 결과", event.get("executionResult")),
        ("동일 조건 재점검", f"{event['verification']} · {event.get('afterValue')}" if event.get("afterAt") else None),
        ("정상 기능 · 롤백 확인", None),
    ]
    return {"eventId": event["id"], "items": [
        {"no": index, "label": label, "value": value, "source": "manual" if index == 12 else event.get("source")}
        for index, (label, value) in enumerate(fields, 1)], "ssmExecutionIds": [], "scanReportKeys": []}




def to_csv(events: list[dict]) -> str:
    columns = [("ID", "id"), ("발생 시각", "at"), ("시나리오", "scenario"), ("제목", "title"),
               ("위험도", "severity"), ("리전", "region"), ("자원", "resource"), ("탐지 소스", "source"),
               ("대응 방식", "mode"), ("상태", "status"), ("실행 결과", "execution"),
               ("재검증", "verification"), ("출발 IP", "sourceIp"), ("위치 상태", "geoStatus")]
    output = io.StringIO(newline="")
    writer = csv.writer(output, quoting=csv.QUOTE_ALL, lineterminator="\r\n")
    writer.writerow([label for label, _ in columns])
    mappings = {"status": STATUS_LABELS, "execution": EXECUTION_LABELS, "verification": VERIFICATION_LABELS,
                "mode": {"AUTO": "자동", "MANUAL": "수동"}}
    for event in events:
        values = []
        for _, key in columns:
            value = event.get(key)
            if key == "at":
                value = datetime.fromtimestamp(value / 1000, timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")
            elif key == "severity":
                value = value.title()
            elif key in mappings:
                value = mappings[key].get(value, value)
            text = "" if value is None else str(value)
            if text.lstrip().startswith(("=", "+", "-", "@")) or text.startswith(("\t", "\r", "\n")):
                text = "'" + text
            values.append(text)
        writer.writerow(values)
    return "\ufeff" + output.getvalue().removesuffix("\r\n")
