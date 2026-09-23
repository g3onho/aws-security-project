"""Data-provider boundary with no generated-observation fallback."""
import hashlib
import os
import threading
import time
from datetime import datetime, timezone
from .errors import Problem
from .store import now_ms


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
            self._session.client("sts", **kwargs).get_caller_identity()
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
            filters = {"RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}]}
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
                "scenario": "SECURITY_HUB", "region": region, "environment": "unknown",
                "resource": resource_id, "source": "Security Hub", "severity": severity,
                "status": "PENDING_APPROVAL", "actionState": "PENDING_APPROVAL", "mode": "MANUAL",
                "execution": "NOT_RUN", "verification": "NOT_RUN", "at": at, "version": 1,
                "planHash": hashlib.sha256(finding_id.encode()).hexdigest(), "actionable": False,
                "allowedActions": [], "history": [], "before": None, "after": None,
                "afterValue": None, "evidence": finding.get("Description"),
                "recommendation": None, "criterion": None, "criterionVersion": None,
                "sourceIp": None, "geoStatus": "unknown", "accountId": finding.get("AwsAccountId"),
                "observedAt": at, "externalFindingId": finding_id,
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
                tags = {t.get("Key"): t.get("Value") for t in instance.get("Tags", [])}
                items.append({"id": instance["InstanceId"], "name": tags.get("Name") or instance["InstanceId"],
                              "role": tags.get("Role") or "EC2",
                              "region": self.region, "accountId": None,
                              "state": (instance.get("State") or {}).get("Name", "unknown"),
                              "type": instance.get("InstanceType")})
        return {"items": items, "total": len(items), "mode": "live"}

    THRESHOLDS = {"cpu": 80, "memory": 80}

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
                "threshold": dict(self.THRESHOLDS),
                "breaches": self._breaches(points, "cpu", self.THRESHOLDS["cpu"]) + self._breaches(points, "memory", self.THRESHOLDS["memory"]),
                "summary": {"samples": len(points), "cpu": {k: stats["cpu"][k] for k in ("max", "avg")},
                            "memory": {k: stats["memory"][k] for k in ("max", "avg")}}}

    def metrics(self, query=None):
        """인프라 모니터링 화면 형식: 선택 호스트 상세 + 전체 호스트 카드(series)."""
        query = query or {}
        window = {"from": int(query.get("from", self.as_of - 86400000)), "to": int(query.get("to", self.as_of))}
        resources = [r for r in self.resources({}).get("items", []) if r["state"] == "running"]
        series = [self._host_view(r, self.metric_for(r, query), window) for r in resources]
        base = {"hosts": resources, "series": series, "thresholds": dict(self.THRESHOLDS),
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
                point[metric] = value
        return {"period": period, "points": [{"at": at, **values} for at, values in sorted(by_at.items())]}

    def vulnerabilities(self, query=None, events=None):
        rows = []
        findings = self._collect(self._client("inspector2"), "list_findings", "findings")
        for finding in findings:
            package = (finding.get("packageVulnerabilityDetails") or {}).get("vulnerablePackages") or [{}]
            package = package[0]
            rows.append({"id": finding.get("findingArn"), "cveId": (finding.get("packageVulnerabilityDetails") or {}).get("vulnerabilityId"),
                         "resource": finding.get("resourceId"), "package": package.get("name"),
                         "severity": str(finding.get("severity", "UNKNOWN")).upper(), "source": "Inspector",
                         "region": finding.get("region") or self.region, "foundAt": self._ms(finding.get("firstObservedAt")),
                         "fixedVersion": package.get("fixedInVersion"), "installedVersion": package.get("version"),
                         "cvss": ((finding.get("inspectorScoreDetails") or {}).get("adjustedCvss") or {}).get("score")})
        return {"items": rows, "total": len(rows), "mode": "live"}

    def services(self, query=None, events=None):
        """Expose EC2 instance health as the first infrastructure component."""
        query = query or {}
        rows = []
        for resource in self.resources(query).get("items", []):
            state = resource.get("state", "unknown")
            rows.append({"id": resource["id"], "name": resource["name"],
                         "status": "UP" if state == "running" else "DOWN",
                         "source": "EC2", "detail": state})
        return {"items": rows, "dependencies": [], "checkedAt": self.as_of, "mode": "live"}

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
