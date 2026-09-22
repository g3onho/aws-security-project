"""취약점(CVE) 목록 — 취약점 점검 화면의 데이터.

이전 구현은 이벤트에서 Trivy·Inspector 건만 걸러 껍데기를 만들고
cveId·cvss·package·installedVersion·fixedVersion 을 전부 None 으로 돌려줬다.
화면도 이 엔드포인트를 부르지 않아 취약점 탭이 이벤트 목록의 복사본이었다.

지금은 `app/catalog/vulnerabilities.yaml` 이 데모 정본이다.
실모드는 이 파일을 쓰지 않는다 — Inspector2 ListFindings 와 Trivy 리포트가 정본이다.

기간 필터를 적용하지 않는 이유:
  취약점 점검 결과는 이벤트가 아니라 **최신 스캔의 현재 상태**다. 15분 구간을 고르면
  스캔이 그 안에 없어 화면이 비는데, 그건 "취약점이 없다"가 아니다.
  대신 각 대상의 스캔 시각을 화면에 같이 내보낸다.
"""
from __future__ import annotations

from ..catalog import loader

SEVERITY_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
SEARCH_FIELDS = ("cveId", "package", "target", "resource")
# 대상 → 조치 시나리오. scenarios.yaml 이 판정 정본이고 여기서는 표시·연결용이다.
KIND_SCENARIO = {"IMAGE": "SEC-04", "INSTANCE": "SEC-04"}


def _scan_times(targets: list[dict], now: int) -> dict[str, int]:
    """대상별 스캔 시각. 카탈로그 순서로 1시간씩 벌려 고정한다(데모 재현성)."""
    return {t["id"]: now - (index + 1) * 3600000 for index, t in enumerate(targets)}


def build_vulnerabilities(events: list[dict], q: dict, now: int, region: str) -> dict:
    catalog = loader.load_vulnerabilities()
    targets = catalog["targets"]
    rows = catalog["vulnerabilities"]
    scanned = _scan_times(targets, now)
    meta = {t["id"]: t for t in targets}

    # 대상별로 조치를 걸 이벤트를 찾는다. 없으면 조치 버튼 대신 이유를 표시한다.
    def link(target_id: str, source: str):
        """조치를 걸 이벤트. 정확 일치 > 이미지 이름 꼬리 일치 > 같은 소스 최신 순.

        데모 이벤트의 Trivy 자원은 `ecr/<region>/app:1.2` 처럼 리전이 끼어 있어
        카탈로그의 `ecr/app:1.2` 와 문자열이 다르다. 꼬리(`app:1.2`)로 잇는다.
        """
        tail = target_id.rsplit("/", 1)[-1]
        by_source = [e for e in events if e.get("source") == source]
        exact = [e for e in by_source if e.get("resource") == target_id]
        suffix = [e for e in by_source if str(e.get("resource") or "").endswith(tail)]
        pool = exact or suffix or by_source
        return max(pool, key=lambda e: e["at"]) if pool else None

    links = {t["id"]: link(t["id"], t["source"]) for t in targets}

    severity = q.get("severity")
    source = q.get("source")
    needle = (q.get("q") or "").lower()
    target_filter = q.get("resource")
    fixable_only = bool(q.get("fixableOnly"))

    items = []
    for row in rows:
        target_id = row["target"]
        info = meta.get(target_id, {})
        if severity and row["severity"] != severity:
            continue
        if source and row["source"] != source:
            continue
        if target_filter and target_id != target_filter:
            continue
        if fixable_only and not row.get("fixedVersion"):
            continue
        item = {
            "id": f"{target_id}::{row['cveId']}",
            "cveId": row["cveId"],
            "source": row["source"],
            "kind": row["kind"],
            "severity": row["severity"],
            "cvss": row.get("cvss"),
            "package": row.get("package"),
            "installedVersion": row.get("installedVersion"),
            "fixedVersion": row.get("fixedVersion"),
            "family": row.get("family"),
            "target": target_id,
            "resource": target_id,
            "region": region,
            "foundAt": scanned.get(target_id),
            "reportKey": (f"trivy/{target_id.replace('/', '_')}.json"
                          if row["source"] == "Trivy" else None),
            "scenario": KIND_SCENARIO.get(row["kind"]),
            "note": info.get("note"),
        }
        if needle:
            hay = " ".join(str(item.get(f) or "") for f in SEARCH_FIELDS).lower()
            if needle not in hay:
                continue
        items.append(item)

    items.sort(key=lambda x: (SEVERITY_RANK.get(x["severity"], 9), -(x["cvss"] or 0), x["cveId"]))

    groups = []
    for target in targets:
        tid = target["id"]
        mine = [x for x in items if x["target"] == tid]
        event = links.get(tid)
        groups.append({
            "target": tid,
            "source": target["source"],
            "kind": target["kind"],
            "note": target.get("note"),
            "scannedAt": scanned.get(tid),
            "total": len(mine),
            "bySeverity": {s: sum(1 for x in mine if x["severity"] == s)
                           for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW")},
            "fixable": sum(1 for x in mine if x["fixedVersion"]),
            # 조치는 CVE 단위가 아니라 대상 단위다(이미지 교체 / 패키지 업데이트).
            "eventId": event["id"] if event else None,
            "eventStatus": event["status"] if event else None,
            "actionable": bool(event and event.get("actionable")),
        })

    return {
        "items": items,
        "nextCursor": None,
        "total": len(items),
        "groups": groups,
        "summary": {
            "total": len(items),
            "bySeverity": {s: sum(1 for x in items if x["severity"] == s)
                           for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW")},
            "fixable": sum(1 for x in items if x["fixedVersion"]),
            "uniqueCves": len({x["cveId"] for x in items}),
            "targets": len(targets),
        },
        "catalogVersion": catalog.get("version"),
        "timeFiltered": False,
    }
