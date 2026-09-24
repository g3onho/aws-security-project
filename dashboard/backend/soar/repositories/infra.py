"""EC2 자원 목록 → 인프라 구성요소 상태."""


def services(resources, checked_at, region):
    """Expose EC2 instance health as the first infrastructure component."""
    rows = []
    for resource in resources.get("items", []):
        state = resource.get("state", "unknown")
        # 화면(serviceFlow)이 읽는 필드를 모두 채운다. 없으면 blockers.length 에서 죽는다.
        rows.append({"id": resource["id"], "name": resource["name"],
                     "status": "UP" if state == "running" else "DOWN",
                     "source": "EC2", "detail": state, "tier": resource.get("role", "EC2"),
                     "port": "-", "latencyMs": None, "errorRate": None,
                     "probe": "ec2:DescribeInstances", "blockers": []})
    overall = "UNKNOWN" if not rows else "UP" if all(r["status"] == "UP" for r in rows) else \
        "DOWN" if all(r["status"] == "DOWN" for r in rows) else "DEGRADED"
    return {"items": rows, "dependencies": [], "checkedAt": checked_at, "mode": "live",
            "overall": overall, "intervalSec": 30, "target": region,
            "note": "EC2 인스턴스 상태 기준입니다(애플리케이션 응답 점검 아님)."}
