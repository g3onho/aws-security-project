"""Data-provider boundary with no generated-observation fallback."""
import hashlib
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
    def _collect(client, operation, key, **kwargs):
        """Collect all pages while keeping small test clients compatible."""
        try:
            pages = client.get_paginator(operation).paginate(**kwargs)
        except (AttributeError, NotImplementedError):
            method = getattr(client, operation)
            return list(method(**kwargs).get(key, []))
        rows = []
        for page in pages:
            rows.extend(page.get(key, []))
        return rows

    @staticmethod
    def _ms(value):
        if isinstance(value, datetime):
            return int(value.astimezone(timezone.utc).timestamp() * 1000)
        return int(value or 0)

    def observations(self, query=None):
        """Normalize Security Hub findings into the dashboard read DTO."""
        query = query or {}
        filters = {}
        if query.get("region") and query["region"] not in {"all", "global"}:
            filters["Region"] = [{"Value": query["region"], "Comparison": "EQUALS"}]
        if query.get("from"):
            # Security Hub 는 Start 만 주면 InvalidInputException — End 를 함께 줘야 한다.
            filters["UpdatedAt"] = [{"Start": datetime.fromtimestamp(int(query["from"]) / 1000, tz=timezone.utc).isoformat(),
                                     "End": datetime.now(timezone.utc).isoformat()}]
        findings = self._collect(self._client("securityhub"), "get_findings", "Findings", **({"Filters": filters} if filters else {}))
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
                items.append({"id": instance["InstanceId"], "name": instance["InstanceId"],
                              "region": self.region, "accountId": None,
                              "state": (instance.get("State") or {}).get("Name", "unknown"),
                              "type": instance.get("InstanceType")})
        return {"items": items, "total": len(items), "mode": "live"}

    def metrics(self, query=None):
        query = query or {}
        resources = self.resources(query).get("items", [])
        points_by_resource = []
        for resource in resources:
            raw = self.metric_for(resource, query)
            points_by_resource.append({"resource": resource["id"], "region": self.region,
                                       "period": raw["period"], "points": raw["points"]})
        return {"hosts": resources, "series": points_by_resource, "thresholds": {"cpu": 80, "memory": 80},
                "periodSeconds": int(query.get("periodSeconds", 300)), "dataMode": "live"}

    def metric_for(self, resource, query=None):
        query = query or {}
        start = datetime.fromtimestamp(int(query.get("from", self.as_of - 86400000)) / 1000, tz=timezone.utc)
        end = datetime.fromtimestamp(int(query.get("to", self.as_of)) / 1000, tz=timezone.utc)
        period = int(query.get("periodSeconds", 300))
        response = self._client("cloudwatch").get_metric_data(
            MetricDataQueries=[{"Id": "cpu", "MetricStat": {"Metric": {"Namespace": "AWS/EC2", "MetricName": "CPUUtilization", "Dimensions": [{"Name": "InstanceId", "Value": resource["id"]}]}, "Period": period, "Stat": "Average"}, "ReturnData": True}],
            StartTime=start, EndTime=end)
        result = (response.get("MetricDataResults") or [{}])[0]
        return {"period": period, "points": [{"at": int(ts.timestamp() * 1000), "cpu": value, "memory": None}
                                                for ts, value in zip(result.get("Timestamps", []), result.get("Values", []))]}

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
