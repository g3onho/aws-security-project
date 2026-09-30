"""모의(데모) AWS 공급자 — DATA_PROVIDER=demo 일 때만 쓴다.

실제 AWS 를 호출하지 않는다. boto3 세션 자리에 가짜 클라이언트(STS·EC2·CloudWatch·Security Hub·Inspector2·
CloudTrail·DynamoDB)를 끼워, 실제 리포지토리·계약 코드가 그대로 돌게 한다. 그래서 화면은 실환경과 같은
경로로 그려지고, 데이터만 모의값이다.

- 계정 000000000000, 공격 IP 는 문서용 예약 대역(RFC 5737)이다. 실제 자원·개인정보가 아니다.
- 시각은 호출 시점 기준 상대값이라 항상 '방금 수집된 것처럼' 보인다. 값 자체는 결정적(같은 입력 → 같은 출력).
- 실제 실패를 가리는 용도로 쓰지 않는다.
- 허니팟·차단 IP 는 모의하지 않는다(설정 없음 → 화면에 '미배포').
- 대시보드 원클릭 조치는 메모리에서만 흉내 낸다(SSM 을 부르지 않는다). 실행은 몇 초 뒤 끝난 것으로 보이고, SSM.6 은 실패를 모의한다.
"""
import hashlib
import math
import os
import zlib
from datetime import datetime, timedelta, timezone

from .guidance import AutoPolicy
from .provider import SERVICE_GROUP_BLOCKED, AwsProvider

ACCOUNT = "000000000000"
REGION = "ap-northeast-2"
PREFIX = "soar-demo"
MIN = 60_000


def _now_ms():
    return int(datetime.now(timezone.utc).timestamp() * 1000)


def _iso(ms):
    return datetime.fromtimestamp(ms / 1000, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000Z")


def _sha(text, n=16):
    return hashlib.sha1(text.encode()).hexdigest()[:n]


# ── EC2 ───────────────────────────────────────────────────────────────
HOSTS = [  # id, name, role, state, type, (cpu base, mem base)
    ("i-0d3m0a1b2c3d40001", "docker-host", "service-3tier", "running", "t3.medium", (34, 62)),
    ("i-0d3m0a1b2c3d40002", "mysql-demo", "database", "running", "t3.small", (22, 58)),
    ("i-0d3m0a1b2c3d40003", "dashboard", "dashboard", "running", "t3.small", (12, 44)),
    ("i-0d3m0a1b2c3d40004", "dvwa-web", "dvwa", "running", "t3.small", (18, 49)),
    ("i-0d3m0a1b2c3d40005", "attack-ec2", "attacker", "stopped", "t3.micro", (0, 0)),
]
BY_ID = {h[0]: h for h in HOSTS}
NAME_ID = {h[1]: h[0] for h in HOSTS}


class _Sts:
    def get_caller_identity(self):
        return {"Account": ACCOUNT, "Arn": f"arn:aws:iam::{ACCOUNT}:role/demo-dashboard"}


class _Ec2:
    def describe_instances(self, Filters=None):
        wanted = None
        for f in Filters or []:
            if f.get("Name") == "instance-id":
                wanted = set(f.get("Values") or [])
        items = []
        for iid, name, role, state, itype, _ in HOSTS:
            if wanted is not None and iid not in wanted:
                continue
            items.append({"InstanceId": iid, "InstanceType": itype, "State": {"Name": state},
                          "Tags": [{"Key": "Name", "Value": name}, {"Key": "Role", "Value": role}],
                          "IamInstanceProfile": {"Arn": f"arn:aws:iam::{ACCOUNT}:instance-profile/{PREFIX}-{name}"}})
        return {"Reservations": [{"Instances": items}]}


# ── CloudWatch ────────────────────────────────────────────────────────
def _noise(*parts):
    return (zlib.crc32("|".join(map(str, parts)).encode()) % 10_000) / 10_000  # 0..1


def _spike(host, metric, t_ms, now):
    """docker-host 에 임계 초과 구간을 만든다(3시간 전 1시간, 30시간 전 40분, 4일 전 2시간)."""
    if host != "docker-host":
        return 0.0
    for start_h, length_min in ((3, 60), (30, 40), (100, 120)):
        start = now - start_h * 60 * MIN
        if start <= t_ms < start + length_min * MIN:
            return 38.0 if metric == "cpu" else 24.0
    return 0.0


def _series(instance_id, metric, start, end, period):
    _, name, _, state, _, (cpu_base, mem_base) = BY_ID[instance_id]
    if state != "running":
        return [], []
    now = _now_ms()
    step = period * 1000
    first = -(-int(start.timestamp() * 1000) // step) * step
    last = min(int(end.timestamp() * 1000), now)
    times, values = [], []
    t = first
    while t <= last:
        base = cpu_base if metric == "cpu" else mem_base
        wave = math.sin((t / 3_600_000) * math.pi / 12 + (0.7 if metric == "cpu" else 2.1))
        amp = 9 if metric == "cpu" else 4
        value = base + amp * wave + (_noise(instance_id, metric, t // step) - 0.5) * (8 if metric == "cpu" else 3)
        value += _spike(name, metric, t, now)
        times.append(datetime.fromtimestamp(t / 1000, tz=timezone.utc))
        values.append(round(min(99.0, max(1.0, value)), 2))
        t += step
    return times, values


class _CloudWatch:
    def get_metric_data(self, MetricDataQueries, StartTime, EndTime, NextToken=None):
        results = []
        for query in MetricDataQueries:
            stat = query["MetricStat"]
            metric = "cpu" if stat["Metric"]["MetricName"] == "CPUUtilization" else "memory"
            instance = next(d["Value"] for d in stat["Metric"]["Dimensions"] if d["Name"] == "InstanceId")
            times, values = _series(instance, metric, StartTime, EndTime, stat["Period"])
            results.append({"Id": query["Id"], "Timestamps": times, "Values": values, "StatusCode": "Complete"})
        return {"MetricDataResults": results}

    def describe_alarms(self, AlarmNamePrefix="", AlarmTypes=None):
        now = datetime.now(timezone.utc)
        topic = f"arn:aws:sns:{REGION}:{ACCOUNT}:{PREFIX}-alerts"

        def alarm(short, state, metric, ns, op, threshold, minutes_ago, reason, dims=None, period=300, evals=2, actions=True):
            return {"AlarmName": f"{PREFIX}-{short}", "StateValue": state, "MetricName": metric, "Namespace": ns,
                    "ComparisonOperator": op, "Threshold": threshold, "Period": period, "EvaluationPeriods": evals,
                    "StateReason": reason, "StateUpdatedTimestamp": now - timedelta(minutes=minutes_ago),
                    "AlarmActions": [topic] if actions else [],
                    "Dimensions": [{"Name": "InstanceId", "Value": v} for v in (dims or [])]}
        gt = "GreaterThanThreshold"
        ge = "GreaterThanOrEqualToThreshold"
        rows = []
        for iid, name, _, state, _, _ in HOSTS[:4]:
            rows.append(alarm(f"{name}-cpu-high", "OK", "CPUUtilization", "AWS/EC2", gt, 80, 190,
                              "Threshold Crossings: no datapoints breaching", [iid]))
            rows.append(alarm(f"{name}-mem-high", "OK", "MemoryUsedPercent", f"{PREFIX}/host", gt, 80, 190,
                              "Threshold Crossings: no datapoints breaching", [iid]))
        rows.append(alarm("attack-ec2-mem-high", "INSUFFICIENT_DATA", "MemoryUsedPercent", f"{PREFIX}/host", gt, 80, 600,
                          "Unchecked: Initial alarm creation", [NAME_ID["attack-ec2"]]))
        rows.append(alarm("mysql-bruteforce", "ALARM", "MySQLAuthFailure", f"{PREFIX}/security", ge, 10, 12,
                          "Threshold Crossed: 1 datapoint [37.0] was greater than or equal to the threshold (10.0).",
                          period=300, evals=1))
        rows.append(alarm("ssh-reject", "OK", "SSHRejectCount", f"{PREFIX}/security", ge, 10, 240,
                          "Threshold Crossings: no datapoints were received for 1 period and 1 missing datapoint was treated as [NonBreaching].",
                          period=300, evals=1))
        rows.append(alarm("waf-sqli", "OK", "BlockedRequests", "AWS/WAFV2", ge, 20, 75,
                          "Threshold Crossings: no datapoints were received for 1 period and 1 missing datapoint was treated as [NonBreaching].",
                          period=300, evals=1))
        rows.append(alarm("finding-sync-errors", "OK", "Errors", "AWS/Lambda", gt, 0, 1300,
                          "Threshold Crossings: no datapoints were received for 1 period and 1 missing datapoint was treated as [NonBreaching].",
                          period=300, evals=1, actions=True))
        return {"MetricAlarms": [r for r in rows if r["AlarmName"].startswith(AlarmNamePrefix)]}


# ── Security Hub (ASFF) ───────────────────────────────────────────────
ATTACKERS = [
    ("198.51.100.23", "China", "Shanghai", 31.23, 121.47),
    ("203.0.113.45", "Russia", "Moscow", 55.75, 37.62),
    ("192.0.2.77", "Brazil", "Sao Paulo", -23.55, -46.63),
    ("198.51.100.99", "United States", "Ashburn", 39.04, -77.49),
    ("203.0.113.8", "Germany", "Frankfurt", 50.11, 8.68),
    ("192.0.2.140", "India", "Mumbai", 19.07, 72.88),
    ("198.51.100.201", "Vietnam", "Hanoi", 21.03, 105.85),
]
GD = "aws/guardduty/service/action/networkConnectionAction/remoteIpDetails/"


def _remote(index):
    ip, country, city, lat, lon = ATTACKERS[index % len(ATTACKERS)]
    return {GD + "ipAddressV4": ip, GD + "country/countryName": country, GD + "city/cityName": city,
            GD + "geoLocation/lat": str(lat), GD + "geoLocation/lon": str(lon)}


def _findings(now):
    out = []

    def add(key, ago_min, product, title, severity, resource, *, region=REGION, types=None, control=None, generator=None,
            rtype="AwsEc2Instance", description="", remote=None, status="FAILED"):
        detector = f"arn:aws:guardduty:{region}:{ACCOUNT}:detector/demo/finding/{_sha(key, 32)}"
        fid = detector if product == "GuardDuty" else f"arn:aws:securityhub:{region}:{ACCOUNT}:finding/{_sha(key, 32)}"
        f = {"Id": fid, "ProductArn": f"arn:aws:securityhub:{region}::product/aws/{product.lower().replace(' ', '')}",
             "ProductName": product, "GeneratorId": generator or (f"security-control/{control}" if control else product),
             "AwsAccountId": ACCOUNT, "Region": region, "Title": title, "Description": description or title,
             "Severity": {"Label": severity}, "CreatedAt": _iso(now - (ago_min + 90) * MIN),
             "UpdatedAt": _iso(now - ago_min * MIN), "RecordState": "ACTIVE", "WorkflowStatus": "NEW",
             "Resources": [{"Id": resource, "Type": rtype, "Region": region}], "Types": types or []}
        if control:
            f["Compliance"] = {"Status": status, "SecurityControlId": control}
        if remote is not None:
            f["ProductFields"] = _remote(remote)
        out.append(f)

    def host(name):
        return f"arn:aws:ec2:{REGION}:{ACCOUNT}:instance/{NAME_ID[name]}"

    ssh = ["TTPs/Initial Access/UnauthorizedAccess:EC2-SSHBruteForce"]
    probe = ["TTPs/Discovery/Recon:EC2-PortProbeUnprotectedPort"]
    # 15분 이내(지금 진행 중인 공격)
    add("ssh-1", 3, "GuardDuty", "SSH brute force attacks against i-docker-host", "HIGH", host("docker-host"), types=ssh, remote=0,
        description="203 회의 SSH 로그인 시도가 관측되었습니다. (모의)")
    add("ssh-2", 9, "GuardDuty", "SSH brute force attacks against i-docker-host", "HIGH", host("docker-host"), types=ssh, remote=1)
    add("probe-1", 13, "GuardDuty", "EC2 instance has an unprotected port which is being probed by a known scanner", "MEDIUM",
        host("dvwa-web"), types=probe, remote=2)
    # 1시간 이내
    add("waf-1", 24, "Security Hub", "WAF 웹 공격 차단 급증 (SQL Injection)", "HIGH", f"arn:aws:wafv2:{REGION}:{ACCOUNT}:regional/webacl/{PREFIX}-web/1",
        generator="soar-waf-alarm", rtype="AwsWafv2WebAcl")
    add("probe-2", 38, "GuardDuty", "EC2 instance has an unprotected port which is being probed by a known scanner", "MEDIUM",
        host("docker-host"), types=probe, remote=3)
    add("ec2-2", 47, "Security Hub", "EC2.2 VPC default security groups should not allow inbound or outbound traffic", "HIGH",
        f"arn:aws:ec2:{REGION}:{ACCOUNT}:security-group/sg-0d3m0default01", control="EC2.2", rtype="AwsEc2SecurityGroup")
    add("ssh-3", 55, "GuardDuty", "SSH brute force attacks against i-dvwa-web", "HIGH", host("dvwa-web"), types=ssh, remote=4)
    # 하루 이내
    add("iam-cred", 130, "GuardDuty", "Credentials for the instance role were used from an external IP address", "CRITICAL",
        f"arn:aws:iam::{ACCOUNT}:role/{PREFIX}-docker-host", region="us-east-1", rtype="AwsIamRole",
        types=["TTPs/Credential Access/UnauthorizedAccess:IAMUser-InstanceCredentialExfiltration.OutsideAWS"], remote=3)
    add("s3-1", 190, "Security Hub", "S3.1 S3 general purpose buckets should have block public access settings enabled", "MEDIUM",
        f"arn:aws:s3:::{PREFIX}-scan-results", control="S3.1", rtype="AwsS3Bucket")
    add("ec2-7", 240, "Security Hub", "EC2.7 EBS default encryption should be enabled", "MEDIUM", f"AWS::::Account:{ACCOUNT}",
        control="EC2.7", rtype="AwsAccount")
    add("bitcoin", 300, "GuardDuty", "EC2 instance is querying a domain name associated with Bitcoin-related activity", "HIGH",
        host("dvwa-web"), types=["TTPs/Command and Control/CryptoCurrency:EC2-BitcoinTool.B!DNS"], remote=6)
    add("iam-7", 420, "Security Hub", "IAM.7 Password policies for IAM users should have strong configurations", "MEDIUM",
        f"AWS::::Account:{ACCOUNT}", control="IAM.7", rtype="AwsAccount")
    add("ssm-6", 610, "Security Hub", "SSM.6 SSM Automation should have CloudWatch logging enabled", "LOW",
        f"arn:aws:ssm:{REGION}:{ACCOUNT}:automation-definition/{PREFIX}-restart", control="SSM.6", rtype="AwsSsmAssociationCompliance")
    add("ec2-18", 720, "Security Hub", "EC2.18 Security groups should only allow unrestricted incoming traffic for authorized ports", "HIGH",
        f"arn:aws:ec2:{REGION}:{ACCOUNT}:security-group/sg-0d3m0web0002", control="EC2.18", rtype="AwsEc2SecurityGroup")
    add("ct-1", 900, "Security Hub", "CloudTrail.5 CloudTrail trails should be integrated with Amazon CloudWatch Logs", "LOW",
        f"arn:aws:cloudtrail:{REGION}:{ACCOUNT}:trail/{PREFIX}-trail", control="CloudTrail.5", rtype="AwsCloudTrailTrail")
    add("ssh-4", 1100, "GuardDuty", "SSH brute force attacks against i-docker-host", "HIGH", host("docker-host"), types=ssh, remote=5)
    add("waf-2", 1250, "Security Hub", "WAF 웹 공격 차단 급증 (XSS)", "MEDIUM",
        f"arn:aws:wafv2:{REGION}:{ACCOUNT}:regional/webacl/{PREFIX}-web/1", generator="soar-waf-alarm", rtype="AwsWafv2WebAcl")
    # 1주일 이내(다른 리전 포함)
    add("tokyo-1", 1700, "Security Hub", "EC2.53 EC2 security groups should not allow ingress from 0.0.0.0/0 to remote server administration ports",
        "HIGH", f"arn:aws:ec2:ap-northeast-1:{ACCOUNT}:security-group/sg-0d3m0tokyo001", region="ap-northeast-1", control="EC2.53",
        rtype="AwsEc2SecurityGroup")
    add("virginia-1", 2400, "GuardDuty", "An API was used to remove protection of a CloudTrail trail", "HIGH",
        f"arn:aws:iam::{ACCOUNT}:user/demo-ci", region="us-east-1", rtype="AwsIamUser",
        types=["TTPs/Defense Evasion/Stealth:IAMUser-CloudTrailLoggingDisabled"], remote=3)
    add("sg-2", 3100, "Security Hub", "EC2.19 Security groups should not allow unrestricted access to ports with high risk", "CRITICAL",
        f"arn:aws:ec2:{REGION}:{ACCOUNT}:security-group/sg-0d3m0db00003", control="EC2.19", rtype="AwsEc2SecurityGroup")
    add("ssh-5", 4300, "GuardDuty", "SSH brute force attacks against i-mysql-demo", "MEDIUM", host("mysql-demo"), types=ssh, remote=1)
    add("ec2-182", 5200, "Security Hub", "EC2.182 Amazon EBS snapshots should not be publicly accessible", "MEDIUM",
        f"AWS::::Account:{ACCOUNT}", control="EC2.182", rtype="AwsAccount")
    add("s3-2", 7000, "Security Hub", "S3.8 S3 general purpose buckets should block public access", "HIGH",
        f"arn:aws:s3:::{PREFIX}-backups", control="S3.8", rtype="AwsS3Bucket")
    add("probe-3", 8800, "GuardDuty", "EC2 instance has an unprotected port which is being probed by a known scanner", "LOW",
        host("dashboard"), types=probe, remote=5)
    return out


class _SecurityHub:
    def get_findings(self, Filters=None, SortCriteria=None, **_):
        rows = _findings(_now_ms())
        for f in (Filters or {}).get("Region", []):
            rows = [r for r in rows if r["Region"] == f["Value"]]
        rows.sort(key=lambda r: r["UpdatedAt"], reverse=True)
        return {"Findings": rows}


# ── Inspector2 ────────────────────────────────────────────────────────
VULNS = [  # cve, package, installed, fixed, manager, severity, cvss, title, exploit, epss
    ("CVE-2024-6387", "openssh-server", "1:8.9p1-3ubuntu0.6", "1:8.9p1-3ubuntu0.10", "OS", "CRITICAL", 8.1, "OpenSSH 서버 신호 처리기 경쟁 조건", True, 0.31),
    ("CVE-2023-4911", "libc6", "2.35-0ubuntu3.1", "2.35-0ubuntu3.4", "OS", "HIGH", 7.8, "glibc ld.so 버퍼 오버플로", True, 0.62),
    ("CVE-2023-38545", "curl", "7.81.0-1ubuntu1.13", "7.81.0-1ubuntu1.14", "OS", "HIGH", 7.5, "curl SOCKS5 핸드셰이크 힙 오버플로", False, 0.09),
    ("CVE-2022-0847", "linux-image-6.2.0-1012-aws", "6.2.0-1012.12", "6.2.0-1017.17", "OS", "HIGH", 7.8, "커널 pipe 권한 상승", True, 0.94),
    ("CVE-2023-44487", "nginx", "1.18.0-6ubuntu14.3", "1.18.0-6ubuntu14.4", "OS", "HIGH", 7.5, "HTTP/2 Rapid Reset 서비스 거부", True, 0.71),
    ("CVE-2023-5678", "openssl", "3.0.2-0ubuntu1.10", "3.0.2-0ubuntu1.12", "OS", "MEDIUM", 5.3, "OpenSSL DH 키 검증 지연", False, 0.01),
    ("CVE-2023-32681", "python3-requests", "2.25.1", "2.31.0", "PYTHONPKG", "MEDIUM", 6.1, "requests Proxy-Authorization 헤더 노출", False, 0.02),
    ("CVE-2023-30861", "Flask", "2.2.2", "2.2.5", "PYTHONPKG", "HIGH", 7.5, "Flask 세션 쿠키 캐시 노출", False, 0.03),
    ("CVE-2023-46136", "Werkzeug", "2.2.2", "3.0.1", "PYTHONPKG", "MEDIUM", 5.9, "Werkzeug 멀티파트 파서 과다 CPU", False, 0.01),
    ("CVE-2023-45803", "urllib3", "1.26.5", "1.26.18", "PYTHONPKG", "MEDIUM", 4.2, "urllib3 리다이렉트 시 요청 본문 유지", False, 0.01),
    ("CVE-2022-31129", "moment", "2.29.1", "2.29.4", "NODEPKG", "LOW", 3.7, "moment 정규식 서비스 거부", False, 0.00),
    ("CVE-2021-3711", "libssl3", "3.0.2-0ubuntu1.10", "3.0.2-0ubuntu1.15", "OS", "LOW", 3.1, "OpenSSL SM2 복호화 버퍼 크기", False, 0.00),
    ("CVE-2023-2650", "openssl", "3.0.2-0ubuntu1.10", "3.0.2-0ubuntu1.11", "OS", "UNTRIAGED", None, "OpenSSL ASN.1 OID 처리 지연", False, 0.01),
    ("CVE-2022-2068", "libc-bin", "2.35-0ubuntu3.1", "2.35-0ubuntu3.3", "OS", "INFORMATIONAL", 2.0, "glibc 참고 항목", False, 0.00),
]
RESOURCES = [  # id, name, type, platform, repo
    (NAME_ID["docker-host"], "docker-host", "AWS_EC2_INSTANCE", "UBUNTU_22_04", None),
    (NAME_ID["dvwa-web"], "dvwa-web", "AWS_EC2_INSTANCE", "UBUNTU_22_04", None),
    (NAME_ID["mysql-demo"], "mysql-demo", "AWS_EC2_INSTANCE", "UBUNTU_22_04", None),
    (f"arn:aws:ecr:{REGION}:{ACCOUNT}:repository/{PREFIX}/flask-app/sha256:{'d3' * 32}", "flask-app", "AWS_ECR_CONTAINER_IMAGE", None, f"{PREFIX}/flask-app"),
]


def _inspector_findings(now):
    rows = []
    for vi, (cve, pkg, ver, fixed, manager, sev, cvss, title, exploit, epss) in enumerate(VULNS):
        for ri, (rid, name, rtype, platform, repo) in enumerate(RESOURCES):
            # 패키지 관리자에 맞는 자원에만 붙인다(OS 패키지는 EC2, 파이썬·노드 패키지는 컨테이너 이미지·대시보드 호스트).
            if manager == "OS" and rtype != "AWS_EC2_INSTANCE":
                continue
            if manager in {"PYTHONPKG", "NODEPKG"} and rtype == "AWS_EC2_INSTANCE" and name != "docker-host":
                continue
            if _noise(cve, rid) < 0.25 and manager == "OS" and ri > 0:
                continue
            first = now - int((2 + 26 * _noise(cve, rid, "f")) * 86_400_000)
            last = now - int(_noise(cve, rid, "l") * 6 * 3_600_000)
            resource = {"id": rid, "type": rtype, "tags": {"Name": name},
                        "details": ({"awsEc2Instance": {"platform": platform}} if rtype == "AWS_EC2_INSTANCE" else
                                    {"awsEcrContainerImage": {"repositoryName": repo, "imageTags": ["latest"]}})}
            rows.append({
                "findingArn": f"arn:aws:inspector2:{REGION}:{ACCOUNT}:finding/{_sha(cve + rid, 32)}",
                "awsAccountId": ACCOUNT, "region": REGION, "resourceId": rid, "severity": sev,
                "title": f"{cve} - {pkg}: {title}", "description": f"{title}. 영향받는 패키지: {pkg} {ver}.",
                "type": "PACKAGE_VULNERABILITY", "status": "ACTIVE", "firstObservedAt": _iso(first), "lastObservedAt": _iso(last),
                "fixAvailable": "YES" if fixed else "NO", "exploitAvailable": "YES" if exploit else "NO",
                "epss": {"score": epss}, "inspectorScoreDetails": {"adjustedCvss": {"score": cvss}} if cvss is not None else {},
                "remediation": {"recommendation": {"text": f"{pkg} 를 {fixed} 이상으로 업데이트하세요."}},
                "packageVulnerabilityDetails": {
                    "vulnerabilityId": cve, "sourceUrl": f"https://nvd.nist.gov/vuln/detail/{cve}",
                    "vulnerablePackages": [{"name": pkg, "version": ver, "fixedInVersion": fixed, "packageManager": manager}]},
                "resources": [resource]})
    return rows


class _Inspector:
    def list_findings(self, filterCriteria=None, **_):
        wanted = {f["value"] for f in (filterCriteria or {}).get("severity", [])}
        rows = _inspector_findings(_now_ms())
        return {"findings": [r for r in rows if not wanted or r["severity"] in wanted]}


class _CloudTrail:
    def lookup_events(self, **_):
        return {"Events": []}


# ── DynamoDB ──────────────────────────────────────────────────────────
def _attr(value):
    """DynamoDB 저장 형식(AttributeValue). boto3 는 integrations/aws 안에서만 import 하므로 직접 만든다."""
    if isinstance(value, bool):
        return {"BOOL": value}
    if isinstance(value, (int, float)):
        return {"N": str(value)}
    if isinstance(value, (list, tuple)):
        return {"L": [_attr(v) for v in value]}
    if isinstance(value, dict):
        return {"M": {k: _attr(v) for k, v in value.items()}}
    return {"S": str(value)}


def _typed(rows):
    return [{k: _attr(v) for k, v in row.items() if v is not None} for row in rows]


def _actions(now):
    ttl = int(now / 1000) + 30 * 86400
    by_key = {}
    for f in _findings(now):
        by_key[f["Id"]] = f
    fs = list(by_key.values())

    def pick(prefix):
        return next(f for f in fs if f["Title"].startswith(prefix))

    def row(i, ago_min, finding, decision, status, control, playbook, reason, before=None, after=None, count=1):
        at = _iso(now - ago_min * MIN)
        return {"action_id": f"asr-{now // 1000 - ago_min * 60}", "created_at": _iso(now - (ago_min + 2) * MIN),
                "updated_at": at, "last_seen_at": at, "finding_id": finding["Id"],
                "finding_type": control if control.startswith(("EC2", "S3", "IAM", "SSM")) else finding["Title"],
                "decision": decision, "status": status, "resource_id": finding["Resources"][0]["Id"],
                "region": finding["Region"], "account_id": ACCOUNT, "playbook_id": playbook, "occurrence_count": count,
                "record_version": 3, "control_id": control, "reason": reason, "before_state": before, "after_state": after,
                "expires_at": ttl}
    return [
        row(1, 46, pick("EC2.2 "), "auto-executed", "SUCCESS", "EC2.2", "ASR-RemoveDefaultSgRules",
            "규칙 ID EC2.2 가 자동 조치 목록에 있고 프로젝트 VPC 의 기본 보안그룹입니다.",
            "인바운드 1개·아웃바운드 1개 규칙", "규칙 0개 (기본 보안그룹 규칙 제거됨)"),
        row(2, 239, pick("EC2.7 "), "auto-executed", "SUCCESS", "EC2.7", "ASR-EnableEbsDefaultEncryption",
            "규칙 ID EC2.7 가 자동 조치 목록에 있습니다. 재부팅 없는 설정 변경입니다.", "EBS 기본 암호화: 꺼짐", "EBS 기본 암호화: 켜짐"),
        row(3, 189, pick("S3.1 "), "auto-executed", "FAILED", "S3.1", "ASR-BlockS3AccountPublicAccess",
            "규칙 ID S3.1 자동 조치. SSM 실행이 실패했습니다(권한 부족 — 모의).", "계정 퍼블릭 액세스 차단: 일부 꺼짐", None),
        row(4, 419, pick("IAM.7 "), "dry-run", "DRY_RUN", "IAM.7", "ASR-SetIamPasswordPolicy",
            "전체 dry-run — 판단만 기록합니다.", None, None),
        row(5, 720, pick("EC2.18 "), "manual-notified", "NOTIFIED", "EC2.18", None,
            "자동 조치 목록 밖 — 담당자에게 SNS 알림만 보냈습니다.", None, None),
        row(6, 3, pick("SSH brute force attacks against i-docker-host"), "auto-executed", "IN_PROGRESS", "SEC-06B",
            "ASR-BlockAttackerNacl", "SSH 접속 거부 급증 알람 → 최다 출발지 IP 를 Private NACL 에 Deny 추가 중.", None, None, 3),
        row(7, 1099, pick("SSH brute force attacks against i-docker-host"), "auto-executed", "NO_CHANGE", "SEC-06B",
            "ASR-BlockAttackerNacl", "이미 NACL 에서 차단 중인 IP 라 실행하지 않았습니다.", None, None, 2),
        row(8, 3099, pick("EC2.19 "), "manual-notified", "NOTIFIED", "EC2.19", None,
            "자동 조치 목록 밖 — 담당자에게 SNS 알림만 보냈습니다.", None, None),
    ]


def _correlations(now):
    gd = next(f for f in _findings(now) if f["Title"].startswith("SSH brute force attacks against i-docker-host"))
    tail = gd["Id"].rsplit("/finding/", 1)[-1]
    return [{"finding_id": tail, "severity_bumped": True, "final_severity": "CRITICAL", "cve_ids": ["CVE-2024-6387"]}]


class _DynamoDb:
    def _rows(self, table):
        now = _now_ms()
        if table == "demo-actions":
            return _actions(now)
        if table == "demo-correlated":
            return _correlations(now)
        return []

    def scan(self, TableName, **_):
        return {"Items": _typed(self._rows(TableName))}

    def query(self, TableName, ExpressionAttributeValues=None, **_):
        wanted = (ExpressionAttributeValues or {}).get(":v", {}).get("S")
        return {"Items": _typed([r for r in self._rows(TableName) if r.get("finding_id") == wanted])}


class FakeSession:
    """boto3.Session 대역. 지원하지 않는 서비스는 조용히 빈 값을 주지 않고 예외로 알린다."""
    CLIENTS = {"sts": _Sts, "ec2": _Ec2, "cloudwatch": _CloudWatch, "securityhub": _SecurityHub,
               "inspector2": _Inspector, "cloudtrail": _CloudTrail, "dynamodb": _DynamoDb}

    def __init__(self, region):
        self.region = region

    def client(self, name, **_):
        if name not in self.CLIENTS:
            raise RuntimeError(f"모의 공급자는 '{name}' 서비스를 지원하지 않습니다.")
        return self.CLIENTS[name]()


DEMO_ENV = {  # 자동 조치 판정 예상(guidance.AutoPolicy)에 쓰는 모의 설정
    "AUTO_REMEDIABLE_PATTERNS": "UnauthorizedAccess:IAMUser",
    "AUTO_REMEDIABLE_CONTROLS": "EC2.2,EC2.7,S3.1,IAM.7,SSM.6,SEC-06A,SEC-06B",
    "ENABLE_AUTO_REMEDIATION": "true",
}


class DemoProvider(AwsProvider):
    def __init__(self, region=REGION, **_):
        os.environ.setdefault("NAME_PREFIX", PREFIX)  # MetricRepository 가 메모리 지표 네임스페이스를 환경변수로 읽는다
        super().__init__(region, session_factory=FakeSession, actions_table="demo-actions",
                         correlated_table="demo-correlated", event_source="securityhub", vulnerability_source="inspector",
                         auto_policy=AutoPolicy(DEMO_ENV["AUTO_REMEDIABLE_PATTERNS"], DEMO_ENV["AUTO_REMEDIABLE_CONTROLS"],
                                                DEMO_ENV["ENABLE_AUTO_REMEDIATION"]),
                         name_prefix=os.environ["NAME_PREFIX"])
        self.demo = True

    def sync_status(self, kind):
        return {"asOf": None, "warnings": []}

    # --- 대시보드 원클릭 조치 모의 ------------------------------------------------------------------
    RUN_SECONDS = 4
    FAILS = {"ASR-EnableSsmAutomationLogging"}          # 실패 경로를 화면에서 볼 수 있게
    PRE_FIXED = {("ASR-RemoveDefaultSgRules", "sg-0d3m0default01"), ("ASR-EnableEbsDefaultEncryption", None)}  # 자동 조치가 이미 고친 것
    UNTAGGED = {"sg-0d3m0web0002"}                       # 회수 허용 태그가 없는 서비스용 보안그룹(웹)

    def _demo_state(self):
        if not hasattr(self, "_fixed"):
            self._fixed, self._runs = set(self.PRE_FIXED), {}
        return self._fixed, self._runs

    @staticmethod
    def _demo_key(plan):
        return plan["playbookId"], plan["parameters"].get("SecurityGroupId")

    def remediation_missing(self):
        return None

    def remediation_measure(self, plan):
        fixed, _ = self._demo_state()
        ok = self._demo_key(plan) in fixed
        return {"compliant": ok, "text": plan["criterion"] + (" — 충족" if ok else " — 미충족")}

    def remediation_precheck(self, plan):
        blocked = None
        if plan["playbookId"] == "ASR-RevokeSecurityGroupIngress" and plan["parameters"]["SecurityGroupId"] in self.UNTAGGED:
            blocked = SERVICE_GROUP_BLOCKED
        return {"blocked": blocked, "overridable": blocked == SERVICE_GROUP_BLOCKED,
                "state": None if blocked else self.remediation_measure(plan)}

    def remediation_start(self, plan, seed):
        _, runs = self._demo_state()
        execution_id = "demo-" + _sha(seed, 12)         # 같은 seed → 같은 실행(SSM ClientToken 과 같은 성질)
        runs.setdefault(execution_id, {"key": self._demo_key(plan), "doc": plan["playbookId"], "at": _now_ms()})
        return execution_id

    def execution(self, execution_id, fetch=True):
        fixed, runs = self._demo_state()
        run = runs.get(execution_id)
        if run is None:
            return super().execution(execution_id, fetch)
        if _now_ms() - run["at"] < self.RUN_SECONDS * 1000:
            return True, {"status": "InProgress", "failureMessage": None, "before": None, "after": None}
        if run["doc"] in self.FAILS:
            return True, {"status": "Failed", "failureMessage": "AccessDeniedException: 권한 부족 (모의)", "before": None, "after": None}
        fixed.add(run["key"])
        return True, {"status": "Success", "failureMessage": None, "before": None, "after": None}
