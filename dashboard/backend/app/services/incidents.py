"""침해사례 보드 — "공격 → 탐지 → 승인 → 조치 → 재검증" 을 시나리오별로 한 줄에 세운다.

설계 근거: 루트 README 2장(침해사례 시나리오)과 12장(대시보드 파트 책임에 '침해사례 탭').

단계 시각은 **이벤트가 실제로 가진 값**에서만 뽑는다. 카탈로그 서술로 단계를 완료
처리하지 않는다 — 발표 화면에서 "했다고 적혀 있는 것"과 "실제로 일어난 것"이 구분돼야 한다.
  탐지    이벤트 발생 시각 (가장 이른 것)
  승인    approvedAt
  조치    execution == SUCCEEDED 가 된 이력 시각
  재검증  afterAt + verification(PASSED/FAILED)
'공격 재현'은 시각이 없다 — 카탈로그의 절차 안내이며 done 을 붙이지 않는다.
"""
from __future__ import annotations

from ..catalog import loader

# 조치 완료로 볼 이력 decision. local/live 어댑터가 쓰는 값이 조금씩 다르다.
EXECUTED_DECISIONS = {"auto-executed", "execute", "completed"}


def _history_at(event: dict, decisions: set[str]):
    for entry in event.get("history") or []:
        if entry.get("decision") in decisions:
            return entry.get("at")
    return None


def _stage(key: str, label: str, done: bool, at, detail: str, tone: str = "ok") -> dict:
    return {"key": key, "label": label, "done": bool(done), "at": at,
            "detail": detail, "tone": tone}


def build_incidents(events: list[dict], q: dict) -> dict:
    """현재 필터 구간의 이벤트로 시나리오별 침해사례 카드를 만든다."""
    from .filters import apply_filters

    in_range = apply_filters(events, q)
    by_scenario: dict[str, list[dict]] = {}
    for event in in_range:
        by_scenario.setdefault(event["scenario"], []).append(event)

    items = []
    for sid in loader.ids():
        spec = loader.get(sid) or {}
        story = loader.incident(sid)
        rows = by_scenario.get(sid, [])
        remediation = spec.get("remediation") or {}

        detected_at = min((e["at"] for e in rows), default=None)
        approved = [e for e in rows if e.get("approvedAt")]
        approved_at = min((e["approvedAt"] for e in approved), default=None)
        executed = [e for e in rows if e.get("execution") == "SUCCEEDED"]
        executed_at = min((x for x in (_history_at(e, EXECUTED_DECISIONS) for e in executed)
                           if x), default=None)
        verified = [e for e in rows if e.get("verification") in ("PASSED", "FAILED")]
        verified_at = max((e.get("afterAt") or e["at"] for e in verified), default=None)
        failed = [e for e in verified if e["verification"] == "FAILED"]

        # 대표 이벤트 — 가장 최근 것. 증적·상세로 바로 넘어갈 수 있게 id 를 싣는다.
        latest = max(rows, key=lambda e: e["at"]) if rows else None

        stages = [
            _stage("attack", "공격 재현", False, None,
                   " / ".join(story.get("attack") or []) or "재현 절차가 카탈로그에 없습니다.",
                   tone="info"),
            _stage("detect", "탐지", bool(rows), detected_at,
                   f"{len(rows)}건 · {', '.join(spec.get('detection') or []) or '탐지 소스 미지정'}"),
            _stage("approve", "승인", bool(approved), approved_at,
                   f"{len(approved)}건 승인됨" if approved
                   else ("자동 조치라 승인 단계가 없습니다." if remediation.get("mode") == "AUTO"
                         else "승인 대기")),
            _stage("execute", "조치 실행", bool(executed), executed_at,
                   f"{len(executed)}건 실행 성공" if executed
                   else ("플레이북 미배선" if not remediation.get("wired") else "미실행")),
            _stage("verify", "재검증", bool(verified), verified_at,
                   (f"{len(verified)}건 재검증 · 실패 {len(failed)}건" if verified else "미실행"),
                   tone="warn" if failed else "ok"),
        ]

        items.append({
            "scenario": sid,
            "title": spec.get("title", ""),
            "severityHint": spec.get("severity_hint"),
            "criterion": spec.get("criterion"),
            "unit": spec.get("unit"),
            "summary": story.get("summary"),
            "basis": story.get("basis"),
            "attack": story.get("attack") or [],
            "trace": story.get("trace") or [],
            "impact": story.get("impact"),
            "control": story.get("control"),
            "note": story.get("note") or remediation.get("note"),
            "detection": spec.get("detection") or [],
            "remediation": {
                "mode": remediation.get("mode"),
                "plannedMode": remediation.get("planned_mode"),
                "playbook": remediation.get("playbook"),
                "wired": bool(remediation.get("wired")),
                "reversible": bool(remediation.get("reversible")),
            },
            "counts": {
                "total": len(rows),
                "open": sum(1 for e in rows if e["status"] != "RESOLVED"),
                "resolved": sum(1 for e in rows if e["status"] == "RESOLVED"),
                "verifyFailed": len(failed),
            },
            "stages": stages,
            "latestEventId": latest["id"] if latest else None,
            "before": (latest or {}).get("before"),
            "after": (latest or {}).get("after"),
        })

    return {"items": items,
            "catalogVersion": loader.load().get("version"),
            "incidentCatalogVersion": loader.load_incidents().get("version")}
