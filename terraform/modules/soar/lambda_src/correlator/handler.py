"""
correlator — GuardDuty finding 을 받아 같은 리소스의 Inspector CVE 와 합칩니다.
둘 다 있으면 심각도를 한 단계 올려 DynamoDB 에 기록합니다. (기획서: 자동 모니터링 #2)
트리거: GuardDuty finding (EventBridge)  /  소비자: Flask 대시보드
"""
import os
import json
import datetime
import boto3

CORRELATED_TABLE = os.environ["CORRELATED_FINDINGS_TABLE"]

inspector = boto3.client("inspector2")
dynamodb = boto3.resource("dynamodb")

SEVERITY_BUMP = {"LOW": "MEDIUM", "MEDIUM": "HIGH", "HIGH": "CRITICAL", "CRITICAL": "CRITICAL"}


def _extract_instance_id(detail):
    resources = detail.get("resource", {})
    inst = resources.get("instanceDetails", {})
    return inst.get("instanceId")


def _cve_list(instance_id):
    try:
        resp = inspector.list_findings(
            filterCriteria={
                "resourceId": [{"comparison": "EQUALS", "value": instance_id}],
                "findingType": [{"comparison": "EQUALS", "value": "PACKAGE_VULNERABILITY"}],
            },
            maxResults=50,
        )
    except Exception as exc:  # noqa: BLE001
        print(f"inspector list_findings failed: {exc}")
        return []
    cves = []
    for f in resp.get("findings", []):
        vd = f.get("packageVulnerabilityDetails", {})
        if vd.get("vulnerabilityId"):
            cves.append(vd["vulnerabilityId"])
    return cves


def handler(event, _context):
    detail = event.get("detail", {})
    finding_id = detail.get("id", event.get("id", "unknown"))
    severity_label = str(detail.get("severity", "")) or "LOW"
    # GuardDuty 는 숫자 severity 를 씁니다. 라벨로 정규화.
    try:
        num = float(severity_label)
        if num >= 7:
            base = "HIGH"
        elif num >= 4:
            base = "MEDIUM"
        else:
            base = "LOW"
    except ValueError:
        base = severity_label.upper() if severity_label.upper() in SEVERITY_BUMP else "LOW"

    instance_id = _extract_instance_id(detail)
    cves = _cve_list(instance_id) if instance_id else []

    final_severity = SEVERITY_BUMP[base] if cves else base
    bumped = bool(cves)

    item = {
        "finding_id": str(finding_id),
        "instance_id": instance_id or "n/a",
        "guardduty_type": detail.get("type", "unknown"),
        "base_severity": base,
        "final_severity": final_severity,
        "severity_bumped": bumped,
        "cve_ids": cves,
        "created_at": datetime.datetime.utcnow().isoformat() + "Z",
    }

    dynamodb.Table(CORRELATED_TABLE).put_item(Item=item)
    print(json.dumps({"correlated": item}))
    return {"statusCode": 200, "bumped": bumped, "cve_count": len(cves)}
