"""3계층 서비스(Nginx → Flask → MySQL) 상태 판정.

왜 필요한가 — 인프라 모니터링 화면의 "3계층 서비스" 카드가 `templates` 안에
`○ 미연동` 으로 **하드코딩**돼 있었다. 화면에 상태 자리는 있는데 그 자리를
채우는 데이터 경로가 아예 없었다는 뜻이다. 이 모듈이 그 경로다.

판정 근거는 모드마다 다르다.

  demo/local — 같은 화면이 쓰는 지표(demo.metrics_for)와 이벤트를 **그대로** 재사용해
    상태를 만든다. 지표에서 CPU 86% 가 나오는 시각이면 Flask 응답시간도 같이 늘어난다.
    임의 난수가 아니라 화면의 다른 숫자와 맞물린다는 점이 핵심이다.
  live — adapters/live.py 의 `services()` 가 ALB 대상 그룹 상태와 CloudWatch 지표로
    같은 모양을 만든다. 프론트는 두 경우를 분기 없이 그린다.

상태 enum: UP / DEGRADED / DOWN / UNKNOWN
"""
from __future__ import annotations

# 계층 정의. 요청 경로 순서대로 둔다(화면의 화살표 순서와 같다).
TIERS = [
    {"id": "nginx", "name": "Nginx", "tier": "web", "port": 80,
     "probe": "GET http://{host}/ (ALB 대상 그룹)", "baseLatency": 11.0, "dependsOn": None,
     "scenarios": ("SEC-02", "SEC-08")},
    {"id": "flask", "name": "Flask", "tier": "app", "port": 5000,
     "probe": "GET http://{host}:5000/health", "baseLatency": 46.0, "dependsOn": "nginx",
     "scenarios": ("SEC-07",)},
    {"id": "mysql", "name": "MySQL", "tier": "db", "port": 3306,
     "probe": "TCP {host}:3306 + mysqladmin ping", "baseLatency": 8.0, "dependsOn": "flask",
     "scenarios": ("SEC-03", "SEC-06")},
]

RANK = {"UP": 0, "DEGRADED": 1, "UNKNOWN": 2, "DOWN": 3}
CHECK_INTERVAL_SEC = 30


def _worse(a: str, b: str) -> str:
    return a if RANK[a] >= RANK[b] else b


def build_services(region: str, at: int, metrics: dict, events: list[dict], mode: str) -> dict:
    """데모/로컬 모드의 계층 상태.

    - 부하 계수: max(CPU, 메모리) / 임계치(80). 1 을 넘으면 응답시간이 늘고 상태가 내려간다.
    - 미해결 이벤트: 계층에 매핑된 시나리오가 미해결이면 그 계층을 DEGRADED 로 본다.
      SEC-03(3306 과다 공개)이 열려 있는데 MySQL 이 초록인 화면은 설명이 안 된다.
    - 의존성 전파: 상류가 DOWN 이면 하류는 정상이어도 요청을 못 받으므로 DEGRADED 로 표시한다.
    """
    from ..adapters.demo import THRESHOLD, _jitter

    host = (metrics or {}).get("host") or {}
    host_id = host.get("id")
    if not host_id:
        return {"region": region, "checkedAt": at, "mode": mode, "overall": "UNKNOWN",
                "target": None, "intervalSec": CHECK_INTERVAL_SEC, "items": [],
                "note": "선택한 리전에 3계층 서비스를 올린 호스트가 없습니다."}

    cpu = metrics.get("cpu") or 0
    memory = metrics.get("memory") or 0
    load = max(cpu, memory) / float(THRESHOLD["cpu"])

    # 미해결 이벤트를 시나리오별로 모아둔다. legacyScenario 는 로컬 어댑터가 붙인다.
    open_by_scenario: dict[str, list[dict]] = {}
    for e in events:
        if e.get("status") == "RESOLVED":
            continue
        for key in (e.get("scenario"), e.get("legacyScenario")):
            if key:
                open_by_scenario.setdefault(key, []).append(e)

    items = []
    by_id: dict[str, dict] = {}
    for spec in TIERS:
        blockers = [e for sid in spec["scenarios"] for e in open_by_scenario.get(sid, [])]
        status = "UP"
        detail = "정상 응답"

        if load > 1.15:
            status, detail = "DOWN", f"상류 자원 포화 · CPU {cpu}% / 메모리 {memory}%"
        elif load > 1.0 and spec["id"] in ("flask", "mysql"):
            status, detail = "DEGRADED", f"자원 임계치 초과 구간 · CPU {cpu}% / 메모리 {memory}%"
        if blockers:
            status = _worse(status, "DEGRADED")
            top = sorted(blockers, key=lambda e: e["at"])[-1]
            detail = f"미해결 {top['scenario']} · {top['title']}"

        factor = 1.0 + max(0.0, load - 1.0) * 2.6
        if status == "DEGRADED":
            factor *= 1.8
        latency = round(spec["baseLatency"] * factor * (0.9 + _jitter(at, spec["port"]) * 0.2), 1)
        error_rate = {"UP": 0.0, "DEGRADED": round(0.4 + _jitter(at, spec["port"] + 7) * 1.7, 2),
                      "DOWN": 100.0, "UNKNOWN": None}[status]

        item = {
            "id": spec["id"], "name": spec["name"], "tier": spec["tier"], "port": spec["port"],
            "status": status, "detail": detail,
            "latencyMs": None if status == "DOWN" else latency,
            "errorRate": error_rate,
            "checkedAt": at, "intervalSec": CHECK_INTERVAL_SEC,
            "target": host_id, "probe": spec["probe"].format(host=host_id),
            "dependsOn": spec["dependsOn"],
            "source": "데모 시계열 + 미해결 이벤트" if mode != "live" else "ALB / CloudWatch",
            "blockers": [{"id": e["id"], "scenario": e["scenario"], "title": e["title"],
                          "severity": e["severity"]} for e in blockers[:3]],
        }
        items.append(item)
        by_id[spec["id"]] = item

    # 의존성 전파는 한 번 더 훑어야 한다(상류가 뒤에 평가될 수 있다).
    for item in items:
        upstream = by_id.get(item["dependsOn"]) if item["dependsOn"] else None
        if upstream and upstream["status"] == "DOWN" and item["status"] == "UP":
            item["status"] = "DEGRADED"
            item["detail"] = f"상류 {upstream['name']} 장애로 요청이 도달하지 않습니다."

    overall = "UP"
    for item in items:
        overall = _worse(overall, item["status"])

    return {
        "region": region, "checkedAt": at, "mode": mode, "overall": overall,
        "target": host_id, "intervalSec": CHECK_INTERVAL_SEC, "items": items,
        "note": None,
    }
