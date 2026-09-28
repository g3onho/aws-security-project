"""Security Hub finding → 대시보드 이벤트 도메인 자료."""
import hashlib

from .. import guidance
from ..integrations.aws.paging import to_ms

DESCRIPTION_LIMIT = 1000  # finding_sync 적재 raw 와 같은 길이 — 직접 조회와 적재 조회 결과가 같게


def classify(finding):
    """탐지 소스(실제 AWS 서비스)와 화면 분류. Security Hub 는 모든 finding 을 모으므로
    source 를 'Security Hub' 하나로 두면 GuardDuty·설정 점검·WAF 가 구분되지 않는다."""
    product = finding.get("ProductName") or "Security Hub"
    if finding.get("GeneratorId") == "soar-waf-alarm":  # soar/lambda_src/waf_finding
        return {"source": "WAF", "scenario": "SEC-08 웹 공격 차단"}
    return {"source": product, "scenario": {"GuardDuty": "위협 탐지", "Security Hub": "보안 설정 점검",
                                            "Config": "설정 규칙 위반", "Inspector": "취약점"}.get(product, product)}


def remote_ip(product_fields):
    """GuardDuty finding 의 공격 출발지 — 통합 관제 지도의 공격 흐름선(map.js connectionMarkup).

    Security Hub 는 GuardDuty 상세를 ProductFields 에 **슬래시 구분** 평평한 키로 넣는다
    (실측 2026-09-22, 삭제 전 app/adapters/live.py _remote_ip 에서 옮김):
        aws/guardduty/service/action/<액션>/remoteIpDetails/ipAddressV4
        .../remoteIpDetails/country/countryName · city/cityName · geoLocation/lat · geoLocation/lon
    액션 종류(awsApiCallAction/networkConnectionAction 등)가 여러 가지라 꼬리만 보고 찾는다.
    좌표가 없으면 sourceLocation 을 비운다 — 지도가 NaN 좌표로 선을 그리지 않게.
    """
    found = {}
    for key, value in (product_fields or {}).items():
        if "remoteIpDetails" not in key or not value:
            continue
        for tail, name in (("/ipAddressV4", "ip"), ("/country/countryName", "country"),
                           ("/city/cityName", "city"), ("/geoLocation/lat", "lat"), ("/geoLocation/lon", "lon")):
            if key.endswith(tail):
                found[name] = str(value)
    if "ip" not in found:
        return {"sourceIp": None, "sourceLocation": None, "geoStatus": "unknown"}
    try:
        lat, lon = float(found["lat"]), float(found["lon"])
    except (KeyError, ValueError):
        lat = lon = None
    location = None if lat is None else {"lat": lat, "lon": lon, "country": found.get("country"),
                                         "city": found.get("city") or found.get("country")}
    status = "located" if location else "country-only" if found.get("country") else "unknown"
    return {"sourceIp": found["ip"], "sourceLocation": location, "geoStatus": status}


def event_id(finding_id):
    """대시보드 이벤트 ID. 조치 이력(finding_id)과 같은 규칙으로 계산해 서로 연결한다."""
    return "SH-" + hashlib.sha1(finding_id.encode()).hexdigest()[:16].upper()


class FindingRepository:
    def __init__(self, securityhub, default_region, policy=None):
        self._securityhub = securityhub
        self._region = default_region
        self._policy = policy  # guidance.AutoPolicy — 자동 조치 판정(설정 기준 예상). 없으면 판정 없음

    def observations(self, query=None):
        """Normalize Security Hub findings into the dashboard read DTO."""
        query = query or {}
        region = query.get("region") if query.get("region") not in {None, "", "all", "global"} else None
        findings = self._securityhub.active(region)
        if query.get("from"):
            start = int(query["from"])
            findings = [f for f in findings if to_ms(f.get("UpdatedAt") or f.get("CreatedAt")) >= start]
        rows = []
        for finding in findings:
            if finding.get("Sample") is True:
                continue  # GuardDuty create-sample-findings 시연용 — 실데이터만 표시한다(ASFF 최상위 Sample)
            finding_id = str(finding.get("Id") or finding.get("ProductArn") or "finding")
            resource = (finding.get("Resources") or [{}])[0]
            resource_id = resource.get("Id") or "unknown-resource"
            region = finding.get("Region") or self._region
            severity = str((finding.get("Severity") or {}).get("Label") or "UNKNOWN").upper()
            if severity not in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}:
                severity = "LOW"
            at = to_ms(finding.get("UpdatedAt") or finding.get("CreatedAt"))
            description = (finding.get("Description") or "")[:DESCRIPTION_LIMIT] or None
            rows.append({
                "id": event_id(finding_id), "title": finding.get("Title") or finding.get("Description") or finding_id,
                **classify(finding), "region": region, "environment": "unknown",
                "resource": resource_id, "severity": severity,
                "status": "PENDING_APPROVAL", "actionState": "PENDING_APPROVAL", "mode": "MANUAL",
                "execution": "NOT_RUN", "verification": "NOT_RUN", "at": at, "version": 1,
                "planHash": hashlib.sha256(finding_id.encode()).hexdigest(), "actionable": False,
                "allowedActions": [], "history": [], "before": None, "after": None,
                "afterValue": None, "evidence": description,
                "recommendation": None, "criterion": None, "criterionVersion": None,
                "accountId": finding.get("AwsAccountId"),
                "observedAt": at, "externalFindingId": finding_id,
                **remote_ip(finding.get("ProductFields")),
                # 탐지 상세: AWS 원문 설명·조치 안내와 팀 설명·자동 조치 판정(guidance.py)
                "description": description, **guidance.annotate(finding, self._policy),
            })
        return rows
