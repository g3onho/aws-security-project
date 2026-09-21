"""SEC 커버리지 보드 — 02-frontend-redesign.md §2.8.

기획서 성공 기준(README:504-513)을 화면 하나로 증명하기 위한 집계.
기본적으로 demo_only 시나리오는 제외한다.
"""
from __future__ import annotations

from ..catalog import loader


def build_coverage(events: list[dict], q: dict) -> dict:
    include_demo = bool(q.get("includeDemoOnly"))
    start, end = q.get("from"), q.get("to")

    from .filters import apply_filters
    in_range = apply_filters(events,q)
    by_scenario: dict[str, list[dict]] = {}
    for e in in_range:
        by_scenario.setdefault(e["scenario"], []).append(e)

    items = []
    for sid in loader.ids(include_demo_only=include_demo):
        spec = loader.get(sid) or {}
        rows = by_scenario.get(sid, [])
        remediation = spec.get("remediation") or {}
        verify = spec.get("verify") or {}

        verified = [e for e in rows if e["verification"] in ("PASSED", "FAILED")]
        last = max((e["afterAt"] or e["at"] for e in verified), default=None)
        if any(e["verification"] == "FAILED" for e in verified):
            v_status = "FAILED"
        elif verified:
            v_status = "PASSED"
        else:
            v_status = "NOT_RUN"

        items.append({
            "scenario": sid,
            "title": spec.get("title", ""),
            "demoOnly": bool(spec.get("demo_only")),
            "detection": {
                "expected": spec.get("detection", []),
                "observed": bool(rows),
                "count": len(rows),
            },
            "remediation": {
                "mode": remediation.get("mode"),
                "plannedMode": remediation.get("planned_mode"),
                "playbook": remediation.get("playbook"),
                "wired": bool(remediation.get("wired")),
                "reversible": bool(remediation.get("reversible")),
                "note": remediation.get("note"),
            },
            "verification": {"status": v_status, "lastAt": last},
            "verifyType": verify.get("type"),
            "needsSendCommand": bool(verify.get("needs_send_command")),
            "blockedBy": verify.get("blocked_by"),
            "evidenceReady": bool(rows) and v_status != "NOT_RUN",
        })

    return {"items": items, "catalogVersion": loader.load().get("version")}
