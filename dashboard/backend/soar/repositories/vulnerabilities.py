"""Inspector finding → 공통 취약점 도메인 자료."""
from ..integrations.aws.paging import to_ms


class VulnerabilityRepository:
    def __init__(self, inspector, session, region):
        self._inspector = inspector
        self._session = session
        self._region = region
        self._memo = None

    def list(self):
        rows = []
        findings = self._inspector.active()
        # 화면은 4933건을 200건씩 25페이지로 받는다. 페이지마다 같은 캐시를 다시 가공하지 않는다.
        # 캐시 목록 객체가 같으면(is) 가공 결과를 재사용한다 — 캐시를 복사하면 재사용이 깨진다.
        if self._memo and self._memo[0] is findings:
            return {"items": self._memo[1], "total": len(self._memo[1]), "mode": "live"}
        for finding in findings:
            package = (finding.get("packageVulnerabilityDetails") or {}).get("vulnerablePackages") or [{}]
            package = package[0]
            first = (finding.get("resources") or [{}])[0]
            rows.append({"id": finding.get("findingArn"), "cveId": (finding.get("packageVulnerabilityDetails") or {}).get("vulnerabilityId"),
                         "resource": finding.get("resourceId") or first.get("id"),
                         # 화면이 i-0581… 대신 서버 이름으로 묶는다. Inspector 가 EC2 태그를 같이 준다.
                         "resourceName": (first.get("tags") or {}).get("Name"),
                         "package": package.get("name"),
                         "severity": str(finding.get("severity", "UNKNOWN")).upper(), "source": "Inspector",
                         "region": finding.get("region") or self._region,
                         "accountId": finding.get("awsAccountId") or self._session.account_id,
                         "foundAt": to_ms(finding.get("firstObservedAt")),
                         "fixedVersion": package.get("fixedInVersion"), "installedVersion": package.get("version"),
                         "cvss": ((finding.get("inspectorScoreDetails") or {}).get("adjustedCvss") or {}).get("score")})
        self._memo = (findings, rows)
        return {"items": rows, "total": len(rows), "mode": "live"}
