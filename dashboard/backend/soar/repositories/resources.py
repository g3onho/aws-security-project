"""EC2 인스턴스 → 대시보드 자원 도메인 자료."""
from ..integrations.aws.ec2 import describe_instances


class ResourceRepository:
    def __init__(self, session, region):
        self._session = session
        self._region = region

    def list(self, query=None):
        query = query or {}
        instance_id = query["resource"] if query.get("resource") and query["resource"] not in {"all"} else None
        items = []
        for instance in describe_instances(self._session, instance_id):
            # 교체된 옛 인스턴스가 1시간가량 목록에 남는다 — 모든 화면에서 뺀다.
            if (instance.get("State") or {}).get("Name") in {"terminated", "shutting-down"}:
                continue
            tags = {t.get("Key"): t.get("Value") for t in instance.get("Tags", [])}
            profile_arn = (instance.get("IamInstanceProfile") or {}).get("Arn") or ""
            items.append({"id": instance["InstanceId"], "name": tags.get("Name") or instance["InstanceId"],
                          "role": tags.get("Role") or "EC2",
                          "profileName": profile_arn.rsplit("/", 1)[-1] if profile_arn else None,
                          "region": self._region, "accountId": self._session.account_id,
                          "state": (instance.get("State") or {}).get("Name", "unknown"),
                          "type": instance.get("InstanceType")})
        return {"items": items, "total": len(items), "mode": "live"}
