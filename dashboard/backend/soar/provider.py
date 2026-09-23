"""Data-provider boundary with no generated-observation fallback."""
import hashlib
import logging
import os
import threading
import time
from datetime import datetime, timezone

from .errors import Problem
from .store import now_ms

THRESHOLDS = {"cpu": 80, "memory": 80}  # 기획서 80% · CloudWatch 알람 임계치와 같게


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


class UnconfiguredProvider:
    connected = False
    regions = ()

    @property
    def as_of(self):
        return now_ms()

    def require_ready(self):
        raise Problem(503, "실데이터 공급자가 연결되지 않았습니다.", "DATA_SOURCE_NOT_CONFIGURED")

    def execution_result(self, event):
        self.require_ready()

    def measure(self, event):
        self.require_ready()

    def status(self):
        return {"connected": False, "state": "not_configured", "detail": "DATA_PROVIDER is not configured"}


class AwsProvider:
    """Read-only AWS data provider used by the dashboard."""
    connected = False
    regions = ()

    def __init__(self, region, session_factory=None):
        self.region = region
        self._session_factory = session_factory
        self._session = None
        self._error = None
        self.account_id = None
        self._clients = {}
        self._findings_cache = {}
        self._findings_lock = threading.Lock()
        self.regions = (region,)
        self._check()

    @property
    def as_of(self):
        return now_ms()

    def _check(self):
        try:
            if self._session_factory is None:
                import boto3
                self._session = boto3.Session(region_name=self.region)
            else:
                self._session = self._session_factory(self.region)
            kwargs = {"region_name": self.region}
            try:
                from botocore.config import Config
                kwargs["config"] = Config(connect_timeout=3, read_timeout=3, retries={"max_attempts": 1})
            except ImportError:
                pass
            self.account_id = self._session.client("sts", **kwargs).get_caller_identity().get("Account")
        except Exception as error:
            self._error = type(error).__name__
            self.connected = False
            return
        self.connected = True

    def require_ready(self):
        if not self.connected:
            raise Problem(503, "AWS 데이터 공급자에 연결할 수 없습니다.", "DATA_SOURCE_UNAVAILABLE")

    def status(self):
        if self.connected:
            return {"connected": True, "state": "credentials_verified", "region": self.region}
        return {"connected": False, "state": "unavailable", "region": self.region,
                "detail": self._error or "connection_failed"}

    def _read_model_not_ready(self):
        self.require_ready()
        raise Problem(501, "AWS 조회 모델이 아직 연결되지 않았습니다.", "READ_MODEL_NOT_CONFIGURED")

    def _client(self, name):
        self.require_ready()
        if name not in self._clients:
            self._clients[name] = self._session.client(name, region_name=self.region)
        return self._clients[name]

    @staticmethod
    def _collect(client, operation, key, max_items=None, **kwargs):
        """Collect all pages while keeping small test clients compatible."""
        try:
            paginator = client.get_paginator(operation)
            if max_items:
                kwargs["PaginationConfig"] = {"MaxItems": max_items, "PageSize": 100}
            pages = paginator.paginate(**kwargs)
        except (AttributeError, NotImplementedError):
            method = getattr(client, operation)
            return list(method(**kwargs).get(key, []))
        rows = []
        for page in pages:
            rows.extend(page.get(key, []))
        return rows

    @staticmethod
    def _ms(value):
        if isinstance(value, str):  # Security Hub(ASFF) 날짜는 ISO 문자열이다.
            value = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if isinstance(value, datetime):
            return int(value.astimezone(timezone.utc).timestamp() * 1000)
        return int(value or 0)

    # GetFindings 한도는 계정당 초당 3회 수준. 화면 한 번에 여러 API 가 이 목록을 쓰고
    # 30초 자동 새로고침까지 겹치면 TooManyRequests 로 전부 죽는다 — 최신 N건만, 잠깐 캐시.
    # ponytail: 프로세스 메모리 캐시(60초). 워커를 여러 프로세스로 늘리면 공유 캐시로.
    FINDINGS_TTL = 60
    FINDINGS_MAX = 500

    def _findings(self, region):
        with self._findings_lock:
            hit = self._findings_cache.get(region)
            if hit and time.monotonic() - hit[0] < self.FINDINGS_TTL:
                return hit[1]
            # Inspector CVE 는 취약점 점검 화면(inspector2 직접 조회)에서 본다. 여기 섞이면
            # ACTIVE 1060건 중 1000건 가까이가 CVE 라 탐지 이벤트가 묻히고 FINDINGS_MAX 에 잘린다(실측 2026-09-23).
            # 통과해 RESOLVED 된 점검(289건)과 INFORMATIONAL 경고(237건)도 탐지가 아니다 — 남는 것은
            # 실패한 점검·위협 탐지 약 90건(실측 2026-09-23). 같은 필드의 NOT_EQUALS 는 AND 로 묶인다.
            filters = {"RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
                       "ProductName": [{"Value": "Inspector", "Comparison": "NOT_EQUALS"}],
                       "WorkflowStatus": [{"Value": "RESOLVED", "Comparison": "NOT_EQUALS"},
                                          {"Value": "SUPPRESSED", "Comparison": "NOT_EQUALS"}],
                       "SeverityLabel": [{"Value": "INFORMATIONAL", "Comparison": "NOT_EQUALS"}]}
            if region:
                filters["Region"] = [{"Value": region, "Comparison": "EQUALS"}]
            findings = self._collect(self._client("securityhub"), "get_findings", "Findings",
                                     max_items=self.FINDINGS_MAX, Filters=filters,
                                     SortCriteria=[{"Field": "UpdatedAt", "SortOrder": "desc"}])
            self._findings_cache[region] = (time.monotonic(), findings)
            return findings

    def observations(self, query=None):
        """Normalize Security Hub findings into the dashboard read DTO."""
        query = query or {}
        region = query.get("region") if query.get("region") not in {None, "", "all", "global"} else None
        findings = self._findings(region)
        if query.get("from"):
            start = int(query["from"])
            findings = [f for f in findings if self._ms(f.get("UpdatedAt") or f.get("CreatedAt")) >= start]
        rows = []
        for finding in findings:
            finding_id = str(finding.get("Id") or finding.get("ProductArn") or "finding")
            resource = (finding.get("Resources") or [{}])[0]
            resource_id = resource.get("Id") or "unknown-resource"
            region = finding.get("Region") or self.region
            severity = str((finding.get("Severity") or {}).get("Label") or "UNKNOWN").upper()
            if severity not in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}:
                severity = "LOW"
            at = self._ms(finding.get("UpdatedAt") or finding.get("CreatedAt"))
            event_id = "SH-" + hashlib.sha1(finding_id.encode()).hexdigest()[:16].upper()
            rows.append({
                "id": event_id, "title": finding.get("Title") or finding.get("Description") or finding_id,
                **classify(finding), "region": region, "environment": "unknown",
                "resource": resource_id, "severity": severity,
                "status": "PENDING_APPROVAL", "actionState": "PENDING_APPROVAL", "mode": "MANUAL",
                "execution": "NOT_RUN", "verification": "NOT_RUN", "at": at, "version": 1,
                "planHash": hashlib.sha256(finding_id.encode()).hexdigest(), "actionable": False,
                "allowedActions": [], "history": [], "before": None, "after": None,
                "afterValue": None, "evidence": finding.get("Description"),
                "recommendation": None, "criterion": None, "criterionVersion": None,
                "accountId": finding.get("AwsAccountId"),
                "observedAt": at, "externalFindingId": finding_id,
                **remote_ip(finding.get("ProductFields")),
                # GuardDuty create-sample-findings 결과. ASFF 최상위 Sample 필드(실측 2026-09-23).
                # 샘플 좌표는 (0,0) 가짜 위치라 지도에서 파란 점선으로 구분한다.
                "sourceSample": finding.get("Sample") is True,
            })
        return rows

    def resources(self, query=None):
        query = query or {}
        filters = []
        if query.get("resource") and query["resource"] not in {"all"}:
            filters.append({"Name": "instance-id", "Values": [query["resource"]]})
        items = []
        reservations = self._collect(self._client("ec2"), "describe_instances", "Reservations", **({"Filters": filters} if filters else {}))
        for reservation in reservations:
            for instance in reservation.get("Instances", []):
                # 교체된 옛 인스턴스가 1시간가량 목록에 남는다 — 모든 화면에서 뺀다.
                if (instance.get("State") or {}).get("Name") in {"terminated", "shutting-down"}:
                    continue
                tags = {t.get("Key"): t.get("Value") for t in instance.get("Tags", [])}
                items.append({"id": instance["InstanceId"], "name": tags.get("Name") or instance["InstanceId"],
                              "role": tags.get("Role") or "EC2",
                              "region": self.region, "accountId": self.account_id,
                              "state": (instance.get("State") or {}).get("Name", "unknown"),
                              "type": instance.get("InstanceType")})
        return {"items": items, "total": len(items), "mode": "live"}


    @staticmethod
    def _breaches(points, metric, limit):
        """임계치를 연속으로 넘은 구간을 묶는다."""
        runs, run = [], None
        for p in points:
            v = p.get(metric)
            if v is not None and v > limit:
                run = run or {"metric": metric, "from": p["at"], "peak": v, "samples": 0}
                run.update(to=p["at"], peak=max(run["peak"], v), samples=run["samples"] + 1)
            elif run:
                runs.append(run); run = None
        return runs + ([run] if run else [])

    def _host_view(self, resource, raw, window):
        points = sorted(raw["points"], key=lambda p: p["at"])
        stats = {}
        for metric in ("cpu", "memory"):
            values = [p[metric] for p in points if p.get(metric) is not None]
            stats[metric] = {"max": round(max(values), 1) if values else None,
                             "avg": round(sum(values) / len(values), 1) if values else None,
                             "last": round(values[-1], 1) if values else None}
        return {"resource": resource["id"], "region": self.region, "period": raw["period"], "window": window,
                "host": {"id": resource["id"], "name": resource["name"], "type": resource.get("type"), "role": resource.get("role", "EC2")},
                "points": points, "cpu": stats["cpu"]["last"], "memory": stats["memory"]["last"],
                "threshold": dict(THRESHOLDS),
                "breaches": self._breaches(points, "cpu", THRESHOLDS["cpu"]) + self._breaches(points, "memory", THRESHOLDS["memory"]),
                "summary": {"samples": len(points), "cpu": {k: stats["cpu"][k] for k in ("max", "avg")},
                            "memory": {k: stats["memory"][k] for k in ("max", "avg")}}}

    def metrics(self, query=None):
        """인프라 모니터링 화면 형식: 선택 호스트 상세 + 전체 호스트 카드(series)."""
        query = query or {}
        window = {"from": int(query.get("from", self.as_of - 86400000)), "to": int(query.get("to", self.as_of))}
        resources = [r for r in self.resources({}).get("items", []) if r["state"] == "running"]
        series = [self._host_view(r, self.metric_for(r, query), window) for r in resources]
        base = {"hosts": resources, "series": series, "thresholds": dict(THRESHOLDS),
                "periodSeconds": int(query.get("periodSeconds", 300)), "dataMode": "live"}
        if not series:
            return base
        selected = next((s for s in series if s["resource"] == query.get("resource")), series[0])
        return {**selected, **base}

    def metric_for(self, resource, query=None):
        query = query or {}
        start = datetime.fromtimestamp(int(query.get("from", self.as_of - 86400000)) / 1000, tz=timezone.utc)
        end = datetime.fromtimestamp(int(query.get("to", self.as_of)) / 1000, tz=timezone.utc)
        period = int(query.get("periodSeconds", 300))
        dims = [{"Name": "InstanceId", "Value": resource["id"]}]
        queries = [{"Id": "cpu", "MetricStat": {"Metric": {"Namespace": "AWS/EC2", "MetricName": "CPUUtilization", "Dimensions": dims}, "Period": period, "Stat": "Average"}, "ReturnData": True}]
        # 메모리는 CloudWatch Agent 가 <NAME_PREFIX>/host 에 올린다(에이전트 없는 호스트는 비어 있음).
        if os.getenv("NAME_PREFIX"):
            queries.append({"Id": "memory", "MetricStat": {"Metric": {"Namespace": os.environ["NAME_PREFIX"] + "/host", "MetricName": "MemoryUsedPercent", "Dimensions": dims}, "Period": period, "Stat": "Average"}, "ReturnData": True})
        response = self._client("cloudwatch").get_metric_data(MetricDataQueries=queries, StartTime=start, EndTime=end)
        by_at = {}
        for result in response.get("MetricDataResults") or []:
            metric = result.get("Id", "cpu")
            for ts, value in zip(result.get("Timestamps", []), result.get("Values", [])):
                point = by_at.setdefault(int(ts.timestamp() * 1000), {"cpu": None, "memory": None})
                point[metric] = round(value, 1)  # 화면에 1.0388888888888888% 로 찍히지 않게
        return {"period": period, "points": [{"at": at, **values} for at, values in sorted(by_at.items())]}

    # 화면은 200건씩 페이지를 받는데 페이지마다 Inspector 전체(수천 건, 수십 초)를 다시 긁으면
    # 취약점 탭이 끝없이 "불러오는 중"이다. ACTIVE 만, 5분 캐시(스캔 결과는 자주 안 바뀐다).
    INSPECTOR_TTL = 300
    # list_findings 는 한 페이지 100건이 상한이라 ACTIVE 4933건 = 51페이지 순차 22초(실측 2026-09-23).
    # 심각도별로 나눠 병렬로 받으면 가장 큰 묶음(UNTRIAGED 2481건) 시간인 약 11초로 준다.
    INSPECTOR_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL", "UNTRIAGED")

    def _fetch_inspector(self):
        from concurrent.futures import ThreadPoolExecutor
        client = self._client("inspector2")

        def part(severity):
            return self._collect(client, "list_findings", "findings", filterCriteria={
                "findingStatus": [{"comparison": "EQUALS", "value": "ACTIVE"}],
                "severity": [{"comparison": "EQUALS", "value": severity}]})
        with ThreadPoolExecutor(len(self.INSPECTOR_SEVERITIES)) as pool:
            findings = [f for rows in pool.map(part, self.INSPECTOR_SEVERITIES) for f in rows]
        self._findings_cache["__inspector__"] = (time.monotonic(), findings)
        return findings

    def _refresh_inspector(self):
        try:
            self._fetch_inspector()
        except Exception:  # noqa: BLE001 — 백그라운드 갱신 실패는 이전 캐시를 계속 쓴다
            logging.getLogger(__name__).exception("inspector refresh failed")
        finally:
            self._inspector_refreshing = False

    def warm(self):
        """앱 기동 직후 취약점 목록을 미리 받아 둔다. 첫 사용자가 11초를 기다리지 않게."""
        if not getattr(self, "_inspector_refreshing", False):
            self._inspector_refreshing = True
            threading.Thread(target=self._refresh_inspector, daemon=True).start()

    def _inspector_findings(self):
        # 만료된 캐시는 그대로 돌려주고 뒤에서 갱신한다(stale-while-revalidate).
        # ponytail: 프로세스 메모리 캐시. 워커를 여러 프로세스로 늘리면 공유 캐시로.
        with self._findings_lock:
            hit = self._findings_cache.get("__inspector__")
            if hit and time.monotonic() - hit[0] >= self.INSPECTOR_TTL:
                self.warm()
            return hit[1] if hit else self._fetch_inspector()

    def vulnerabilities(self, query=None, events=None):
        rows = []
        findings = self._inspector_findings()
        # 화면은 4933건을 200건씩 25페이지로 받는다. 페이지마다 같은 캐시를 다시 가공하지 않는다.
        memo = getattr(self, "_vuln_rows", None)
        if memo and memo[0] is findings:
            return {"items": memo[1], "total": len(memo[1]), "mode": "live"}
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
                          "region": finding.get("region") or self.region,
                          "accountId": finding.get("awsAccountId") or self.account_id,
                          "foundAt": self._ms(finding.get("firstObservedAt")),
                         "fixedVersion": package.get("fixedInVersion"), "installedVersion": package.get("version"),
                         "cvss": ((finding.get("inspectorScoreDetails") or {}).get("adjustedCvss") or {}).get("score")})
        self._vuln_rows = (findings, rows)
        return {"items": rows, "total": len(rows), "mode": "live"}

    def services(self, query=None, events=None):
        """Expose EC2 instance health as the first infrastructure component."""
        query = query or {}
        rows = []
        for resource in self.resources(query).get("items", []):
            state = resource.get("state", "unknown")
            # 화면(serviceFlow)이 읽는 필드를 모두 채운다. 없으면 blockers.length 에서 죽는다.
            rows.append({"id": resource["id"], "name": resource["name"],
                         "status": "UP" if state == "running" else "DOWN",
                         "source": "EC2", "detail": state, "tier": resource.get("role", "EC2"),
                         "port": "-", "latencyMs": None, "errorRate": None,
                         "probe": "ec2:DescribeInstances", "blockers": []})
        overall = "UNKNOWN" if not rows else "UP" if all(r["status"] == "UP" for r in rows) else \
            "DOWN" if all(r["status"] == "DOWN" for r in rows) else "DEGRADED"
        return {"items": rows, "dependencies": [], "checkedAt": self.as_of, "mode": "live",
                "overall": overall, "intervalSec": 30, "target": self.region,
                "note": "EC2 인스턴스 상태 기준입니다(애플리케이션 응답 점검 아님)."}

    def scenarios(self, query=None, events=None):
        events = events if events is not None else self.observations(query)
        return {"items": [{"id": row["scenario"], "name": row["scenario"],
                            "eventCount": sum(item["scenario"] == row["scenario"] for item in events)}
                           for row in {event["scenario"]: event for event in events}.values()],
                "total": len({event["scenario"] for event in events}), "mode": "live"}

    def incidents(self, query=None, events=None):
        events = events if events is not None else self.observations(query)
        return {"items": events, "total": len(events), "mode": "live"}

    def execution_result(self, event):
        raise Problem(403, "실제 조치 공급자는 아직 활성화되지 않았습니다.", "ACTION_PROVIDER_DISABLED")

    def measure(self, event):
        raise Problem(403, "실제 재검증 공급자는 아직 활성화되지 않았습니다.", "ACTION_PROVIDER_DISABLED")

    def __getattr__(self, name):
        if name in {"metrics", "services", "resources", "nacls", "vulnerabilities", "scenarios", "incidents"}:
            return lambda *args, **kwargs: self._read_model_not_ready()
        raise AttributeError(name)
