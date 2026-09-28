"""Inspector finding → 공통 취약점 도메인 자료."""
import re

from ..integrations.aws.paging import to_ms

# finding_sync 적재 raw 와 같은 길이 제한 — 직접 조회와 적재 조회 결과가 같게(v21 동등성 검사).
TITLE_LIMIT, DESCRIPTION_LIMIT, REMEDIATION_LIMIT, TAG_LIMIT = 300, 1000, 500, 3
KERNEL = re.compile(r"^(linux-(image|headers|modules|aws|kvm|generic|tools|virtual)|kernel)", re.IGNORECASE)
SAFE_PACKAGE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+_:~-]{0,127}$")
SAFE_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+_:~-]{0,63}$")
FIX_METHOD = {"AWS_EC2_INSTANCE": "package-update", "AWS_ECR_CONTAINER_IMAGE": "image-rebuild",
              "AWS_LAMBDA_FUNCTION": "function-update"}


def _https(url):
    return url if isinstance(url, str) and url.startswith("https://") else None


def update_command(package, resource_type, platform):
    """업데이트 명령. Inspector 가 준 명령이 있으면 그대로, 없으면 OS·언어 패키지에 한해 만든다.
    (명령, 출처) — 출처는 inspector / generated. 만들 수 없으면 (None, None)."""
    given = (package.get("remediation") or "")[:REMEDIATION_LIMIT]
    if given:
        return given, "inspector"
    name, fixed, manager = package.get("name"), package.get("fixedInVersion"), str(package.get("packageManager") or "")
    if not name or not SAFE_PACKAGE.match(name) or resource_type != "AWS_EC2_INSTANCE":
        return None, None
    platform = str(platform or "").upper()
    if manager == "OS":
        if platform.startswith(("UBUNTU", "DEBIAN")):
            return f"sudo apt-get update && sudo apt-get install --only-upgrade -y {name}", "generated"
        if platform.startswith(("AMAZON_LINUX_2023", "RHEL", "ROCKY", "ALMA", "CENTOS_STREAM")):
            return f"sudo dnf upgrade -y {name}", "generated"
        if platform.startswith(("AMAZON_LINUX_2", "CENTOS")):
            return f"sudo yum update -y {name}", "generated"
        return None, None
    if not fixed or not SAFE_VERSION.match(fixed):
        return None, None
    if manager in {"PIP", "PYTHONPKG", "PIPENV", "POETRY"}:
        return f"pip install --upgrade '{name}=={fixed}'", "generated"
    if manager in {"NPM", "NODEPKG", "YARN"}:
        return f"npm install {name}@{fixed}", "generated"
    return None, None


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
            details = finding.get("packageVulnerabilityDetails") or {}
            package = (details.get("vulnerablePackages") or [{}])[0]
            first = (finding.get("resources") or [{}])[0]
            resource_details = first.get("details") or {}
            ecr = resource_details.get("awsEcrContainerImage") or {}
            platform = (resource_details.get("awsEc2Instance") or {}).get("platform")
            resource_type = first.get("type")
            cve = details.get("vulnerabilityId")
            command, command_source = update_command(package, resource_type, platform)
            is_kernel = bool(package.get("name") and KERNEL.match(package["name"]))
            recommendation = ((finding.get("remediation") or {}).get("recommendation") or {})
            rows.append({"id": finding.get("findingArn"), "cveId": cve,
                         "resource": finding.get("resourceId") or first.get("id"),
                         # 화면이 i-0581… 대신 서버 이름으로 묶는다. Inspector 가 EC2 태그를 같이 준다.
                         "resourceName": (first.get("tags") or {}).get("Name"),
                         "package": package.get("name"),
                         "severity": str(finding.get("severity", "UNKNOWN")).upper(), "source": "Inspector",
                         "region": finding.get("region") or self._region,
                         "accountId": finding.get("awsAccountId") or self._session.account_id,
                         "foundAt": to_ms(finding.get("firstObservedAt")),
                         "lastSeenAt": to_ms(finding.get("lastObservedAt")) if finding.get("lastObservedAt") else None,
                         "fixedVersion": package.get("fixedInVersion"), "installedVersion": package.get("version"),
                         "cvss": ((finding.get("inspectorScoreDetails") or {}).get("adjustedCvss") or {}).get("score"),
                         # 왜 위험한지·어떻게 고치는지(Inspector 원문 + 업데이트 명령·재부팅 여부)
                         "title": (finding.get("title") or "")[:TITLE_LIMIT] or None,
                         "description": (finding.get("description") or "")[:DESCRIPTION_LIMIT] or None,
                         "remediation": (recommendation.get("text") or "")[:REMEDIATION_LIMIT] or None,
                         "fixAvailable": finding.get("fixAvailable"), "exploitAvailable": finding.get("exploitAvailable"),
                         "epss": (finding.get("epss") or {}).get("score"),
                         "packageManager": package.get("packageManager"),
                         "updateCommand": command, "updateCommandSource": command_source,
                         "resourceType": resource_type, "platform": platform,
                         "repository": ecr.get("repositoryName"), "imageTags": list(ecr.get("imageTags") or [])[:TAG_LIMIT],
                         "fixMethod": FIX_METHOD.get(resource_type),
                         # 커널 패키지는 새 커널로 부팅해야 적용된다. EC2 가 아니면(이미지 재빌드 등) 판단하지 않는다.
                         "rebootRequired": is_kernel if resource_type == "AWS_EC2_INSTANCE" else None,
                         "referenceUrl": (f"https://nvd.nist.gov/vuln/detail/{cve}" if cve and re.match(r"^CVE-\d{4}-\d+$", cve)
                                          else _https(details.get("sourceUrl")))})
        self._memo = (findings, rows)
        return {"items": rows, "total": len(rows), "mode": "live"}
