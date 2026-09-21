"""실 AWS 어댑터 — 조회 구현, 쓰기는 스텁.

demo/local 과 **같은 Event 스키마**를 돌려준다. 프론트는 /health 의 mode 로
어느 쪽이 붙었는지 알 뿐, 응답 모양은 동일하다.

조회 경로
  list_events      securityhub:GetFindings + dynamodb:Scan(correlated)
  get_event        위 목록에서 단건 (상류에 단건 조회 API 가 없다)
  metrics          cloudwatch:GetMetricData (CPUUtilization · mem_used_percent)
  vulnerabilities  inspector2:ListFindings (PACKAGE_VULNERABILITY)
  scenarios        카탈로그 + 위 목록 집계
  evidence         위 전부
  execution_status ssm:GetAutomationExecution

쓰기(approve/execute/verify/cancel)는 501 스텁으로 남긴다.
`run.py:41` 이 실모드에서 WRITE_ENABLED 를 강제로 끄므로 어차피 도달하지 않는다.
읽기 전용 단계(M2)를 지나 쓰기를 열 때 구현한다 — 04-backend-design.md §3.

알아둘 것
  - **시각은 전부 epoch ms 정수로 변환한다.** correlated 테이블의 created_at 은
    ISO 문자열이라(`correlator/handler.py:76`) 그대로 내보내면 프론트 필터가 깨진다.
  - 조치 이력은 remediation_actions 를 `finding_id` 로 조인해 붙인다.
    `asr_trigger/handler.py` 가 이 값을 기록한다. DynamoDB 는 스키마리스라
    테이블 정의(`aws_dynamodb_table`)는 바꿀 필요가 없었다 — 키가 아닌 속성이다.
    테이블이 설정되지 않았을 때만 `historyNote` 로 이유를 밝힌다.
"""
from __future__ import annotations

import threading
import time
from datetime import datetime, timezone

from .. import enums
from ..api.errors import ApiProblem
from ..catalog import loader

# ponytail: correlated 테이블에 시간 GSI 가 없어 Scan 한다.
# 발표용 계정 규모에서 넉넉하고, 넘치면 GSI 를 파고 Query 로 바꾼다.
MAX_ITEMS = 200

NO_ACTIONS_TABLE_NOTE = (
    "REMEDIATION_ACTIONS_TABLE 이 설정되지 않아 조치 이력을 붙이지 못했습니다. "
    "탐지 항목만 표시합니다."
)

# asr_trigger 의 decision 값 → 화면 문구
DECISION_TEXT = {
    "auto-executed": "자동 조치 실행",
    "manual-notified": "수동 조치 알림 발송 · 승인 대기",
    "dry-run": "dry-run 판정 · 실행하지 않음",
}

WRITE_PLAN = {
    "approve": "dynamodb:PutItem(actions, decision=approved)",
    "execute": "게이트 판정 → ssm:StartAutomationExecution + iam:PassRole → dynamodb:PutItem",
    "verify": "verify.type 별 재검사 (04 §3.4)",
    "cancel": "ssm:StopAutomationExecution — 대시보드 역할에 권한이 없다",
}


def _now_ms() -> int:
    return int(time.time() * 1000)


def _ms(value) -> int | None:
    """AWS 가 주는 여러 시각 표기를 epoch ms 정수로 통일한다."""
    if value in (None, ""):
        return None
    if isinstance(value, datetime):
        at = value if value.tzinfo else value.replace(tzinfo=timezone.utc)
        return int(at.timestamp() * 1000)
    if isinstance(value, (int, float)):
        return int(value * 1000) if value < 1e12 else int(value)
    try:
        at = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        at = at if at.tzinfo else at.replace(tzinfo=timezone.utc)
        return int(at.timestamp() * 1000)
    except ValueError:
        return None


def _region_of(arn: str, default: str) -> str:
    parts = (arn or "").split(":")
    return parts[3] if len(parts) > 3 and parts[3] else default


def _round(values, index):
    if not values or index >= len(values):
        return None
    return round(float(values[index]), 1)


class LiveAdapter:
    mode = "live"

    def __init__(self, config) -> None:
        self.config = config
        self._lock = threading.Lock()
        self._clients: dict[str, object] = {}
        self._cache: dict[str, tuple[float, object]] = {}

    # ── 상류 호출 ───────────────────────────────────────
    def _client(self, name: str):
        with self._lock:
            if name not in self._clients:
                try:
                    import boto3  # noqa: PLC0415
                except ImportError as exc:
                    raise ApiProblem(
                        503, "실 AWS 연동을 쓸 수 없습니다.", code="AWS_UNAVAILABLE",
                        detail="requirements.txt 의 boto3 를 설치해야 실모드가 동작합니다.",
                    ) from exc
                self._clients[name] = boto3.client(name, region_name=self.config.AWS_REGION)
            return self._clients[name]

    def _call(self, service: str, op: str, **kwargs):
        """상류 1회 호출.

        예외 메시지를 그대로 노출하지 않는다 — 권한 오류 본문에 ARN 이 섞인다
        (04-backend-design.md §4.3). 타입 이름만 detail 로 남긴다.
        """
        try:
            return getattr(self._client(service), op)(**kwargs)
        except ApiProblem:
            raise
        except Exception as exc:  # noqa: BLE001
            raise ApiProblem(
                502, f"{service} 조회에 실패했습니다.", code="UPSTREAM_ERROR",
                detail=type(exc).__name__,
            ) from exc

    def _cached(self, key: str, ttl: int, build):
        hit = self._cache.get(key)
        if hit and time.time() - hit[0] < ttl:
            return hit[1]
        value = build()
        self._cache[key] = (time.time(), value)
        return value

    # ── 이벤트 조립 ─────────────────────────────────────
    def _correlated(self) -> dict[str, dict]:
        """correlator 결과를 finding_id 로 색인한다. 테이블 미설정이면 빈 dict."""
        table = self.config.CORRELATED_FINDINGS_TABLE
        if not table:
            return {}
        page = self._call("dynamodb", "scan", TableName=table, Limit=MAX_ITEMS)
        out = {}
        for raw in page.get("Items", []):
            item = {k: next(iter(v.values())) for k, v in raw.items()}
            cves = [c.get("S", c) if isinstance(c, dict) else c
                    for c in (item.get("cve_ids") or [])]
            out[str(item.get("finding_id"))] = {
                "cveIds": cves,
                "severityBumped": str(item.get("severity_bumped")).lower() == "true",
                "finalSeverity": item.get("final_severity"),
                "instanceId": item.get("instance_id"),
                "at": _ms(item.get("created_at")),
                "guarddutyType": item.get("guardduty_type") or "",
            }
        return out

    def _actions(self) -> dict[str, list[dict]]:
        """조치 이력을 finding_id 로 묶는다. 테이블 미설정이면 빈 dict.

        asr_trigger 가 판정할 때마다 한 행씩 쌓으므로 한 finding 에 여러 건이 온다.
        오래된 것부터 정렬해 history 순서를 그대로 쓴다.
        """
        table = self.config.REMEDIATION_ACTIONS_TABLE
        if not table:
            return {}
        page = self._call("dynamodb", "scan", TableName=table, Limit=MAX_ITEMS)
        out: dict[str, list[dict]] = {}
        for raw in page.get("Items", []):
            item = {k: next(iter(v.values())) for k, v in raw.items()}
            finding_id = str(item.get("finding_id") or "")
            # 예전 행에는 finding_id 가 없다. 조인할 수 없으므로 버린다.
            if not finding_id or finding_id == "unknown":
                continue
            out.setdefault(finding_id, []).append({
                "at": _ms(item.get("created_at")),
                "decision": str(item.get("decision") or ""),
                "beforeState": str(item.get("before_state") or ""),
                "afterState": str(item.get("after_state") or ""),
                "executionId": str(item.get("ssm_execution_id") or ""),
            })
        for rows in out.values():
            rows.sort(key=lambda r: r["at"] or 0)
        return out

    def _build_events(self) -> list[dict]:
        correlated = self._correlated()
        actions = self._actions()
        page = self._call(
            "securityhub", "get_findings",
            Filters={"RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}]},
            MaxResults=MAX_ITEMS,
        )

        events, seen = [], set()
        for f in page.get("Findings", []):
            finding_id = str(f.get("Id") or "")
            if not finding_id:
                continue
            seen.add(finding_id)
            events.append(self._from_finding(f, correlated.get(finding_id),
                                             actions.get(finding_id)))

        # correlator 만 알고 Security Hub 에 안 올라온 GuardDuty finding 도 보여준다.
        for finding_id, extra in correlated.items():
            if finding_id not in seen:
                events.append(self._from_correlated(finding_id, extra,
                                                    actions.get(finding_id)))

        events.sort(key=lambda e: e["at"] or 0, reverse=True)
        return events

    def _from_finding(self, f: dict, extra: dict | None,
                      actions: list[dict] | None = None) -> dict:
        product = (f.get("ProductFields") or {}).get("aws/securityhub/ProductName", "")
        source = enums.PRODUCT_TO_SOURCE.get(product, "Security Hub")
        generator = str(f.get("GeneratorId") or "")
        gd_type = (extra or {}).get("guarddutyType") or (f.get("Types") or [""])[0]
        resource = (f.get("Resources") or [{}])[0].get("Id") or "n/a"
        return self._event(
            event_id=str(f.get("Id")),
            scenario=loader.classify(source=source, generator=generator, gd_type=gd_type),
            title=f.get("Title") or generator or "미분류 finding",
            severity=(extra or {}).get("finalSeverity")
            or (f.get("Severity") or {}).get("Label") or "LOW",
            source=source,
            region=_region_of(resource, self.config.AWS_REGION),
            resource=resource,
            at=_ms(f.get("UpdatedAt") or f.get("CreatedAt")) or _now_ms(),
            evidence=f.get("Description") or "",
            recommendation=((f.get("Remediation") or {}).get("Recommendation") or {}).get("Text", ""),
            extra=extra,
            actions=actions,
        )

    def _from_correlated(self, finding_id: str, extra: dict,
                         actions: list[dict] | None = None) -> dict:
        gd_type = extra.get("guarddutyType") or ""
        return self._event(
            event_id=finding_id,
            scenario=loader.classify(source="GuardDuty", gd_type=gd_type),
            title=gd_type or "GuardDuty finding",
            severity=extra.get("finalSeverity") or "LOW",
            source="GuardDuty",
            region=self.config.AWS_REGION,
            resource=extra.get("instanceId") or "n/a",
            at=extra.get("at") or _now_ms(),
            evidence="GuardDuty 탐지 + Inspector CVE 상관분석 결과",
            recommendation="",
            extra=extra,
            actions=actions,
        )

    def _event(self, *, event_id, scenario, title, severity, source, region,
               resource, at, evidence, recommendation, extra, actions=None) -> dict:
        """demo.py `_build_events()` 와 같은 필드 집합을 채운다."""
        extra = extra or {}
        wired = loader.is_wired(scenario) if scenario else False
        mode = "AUTO" if wired else "MANUAL"

        # 조치 이력을 탐지 항목 뒤에 이어 붙이고, 마지막 판정으로 상태를 정한다.
        history = [{"at": at, "text": "탐지 근거 수집", "actor": None, "decision": None}]
        status = "NEW" if mode == "AUTO" else "PENDING_APPROVAL"
        execution, verification = "NOT_RUN", "NOT_RUN"
        after_at, after_value = None, None
        for action in actions or []:
            decision = action["decision"]
            text = DECISION_TEXT.get(decision, decision or "조치 판정")
            if action["afterState"] and action["afterState"] != "pending":
                text = f"{text} · {action['afterState']}"
            history.append({"at": action["at"], "text": text,
                            "actor": None, "decision": decision})
            if decision == "auto-executed":
                # SSM 이 실제로 끝났는지는 execution_status() 로 따로 확인한다.
                status, execution = "PENDING_VERIFICATION", "SUCCEEDED"
                after_at, after_value = action["at"], action["afterState"] or None
            elif decision == "manual-notified":
                status = "PENDING_APPROVAL"
        return {
            "id": event_id,
            "scenario": scenario or "UNCLASSIFIED",
            "title": title,
            "severity": severity if severity in enums.SEVERITY_ORDER else "LOW",
            "source": source,
            "mode": mode,
            "region": region,
            "environment": "production",
            "resource": resource,
            "at": at,
            "status": status,
            "execution": execution,
            "verification": verification,
            "criterion": loader.criterion(scenario) if scenario else "",
            "unit": loader.unit(scenario) if scenario else "",
            "before": None,
            "after": None,
            "beforeAt": at,
            "afterAt": after_at,
            "afterValue": after_value,
            "evidence": evidence,
            "recommendation": recommendation,
            # 위치 정보는 데모 전용이다. 실모드는 GeoIP 를 호출하지 않는다.
            "sourceIp": None,
            "sourceLocation": None,
            "geoStatus": "해당 없음",
            "history": history,
            "historyNote": None if self.config.REMEDIATION_ACTIONS_TABLE else NO_ACTIONS_TABLE_NOTE,
            "playbook": loader.playbook(scenario) if scenario else None,
            "cveIds": extra.get("cveIds") or [],
            "severityBumped": bool(extra.get("severityBumped")),
            "approver": None,
            "approvedAt": None,
        }

    def _events(self) -> list[dict]:
        return self._cached("events", self.config.CACHE_TTL["events"], self._build_events)

    # ── 조회 ────────────────────────────────────────────
    def list_events(self, q: dict) -> dict:
        from ..services.filters import apply_filters, paginate
        return paginate(apply_filters(self._events(), q), q)

    def snapshot(self, q: dict) -> dict:
        """CSV 내보내기용 — 페이지네이션 없이 필터 결과 전부."""
        from ..services.filters import apply_filters
        return {"items": apply_filters(self._events(), q)}

    def get_event(self, event_id: str):
        return next((e for e in self._events() if e["id"] == event_id), None)

    def scenarios(self, q: dict) -> dict:
        from ..services.scenarios import build_coverage
        return build_coverage(self._events(), q)

    def evidence(self, event_id: str):
        from ..services.evidence import build_evidence
        event = self.get_event(event_id)
        if not event:
            return None
        ids = [a["executionId"] for a in self._actions().get(event_id, [])
               if a["executionId"] and a["executionId"] != "n/a"]
        return build_evidence(event, ssm_execution_ids=ids)

    def metrics(self, q: dict) -> dict:
        instance = self._first_instance()
        if not instance:
            return {"resource": None, "at": None, "cpu": None, "memory": None,
                    "threshold": {"cpu": 80, "memory": 80}, "points": [],
                    "note": "지표를 조회할 EC2 인스턴스를 찾지 못했습니다."}

        period = max(60, (q["to"] - q["from"]) // 1000 // 12)
        resp = self._call(
            "cloudwatch", "get_metric_data",
            MetricDataQueries=[
                _metric_query("cpu", "AWS/EC2", "CPUUtilization", instance, period),
                _metric_query("mem", "CWAgent", "mem_used_percent", instance, period),
            ],
            StartTime=datetime.fromtimestamp(q["from"] / 1000, tz=timezone.utc),
            EndTime=datetime.fromtimestamp(q["to"] / 1000, tz=timezone.utc),
            ScanBy="TimestampAscending",
        )
        series = {r["Id"]: r for r in resp.get("MetricDataResults", [])}
        cpu, mem = series.get("cpu", {}), series.get("mem", {})
        stamps = cpu.get("Timestamps") or mem.get("Timestamps") or []
        points = [{"at": _ms(stamps[i]),
                   "cpu": _round(cpu.get("Values"), i),
                   "memory": _round(mem.get("Values"), i)}
                  for i in range(len(stamps))]
        return {
            "resource": instance,
            "at": points[-1]["at"] if points else None,
            "cpu": points[-1]["cpu"] if points else None,
            "memory": points[-1]["memory"] if points else None,
            "threshold": {"cpu": 80, "memory": 80},
            "points": points,
            "note": None if points else "선택한 기간에 지표 데이터가 없습니다.",
        }

    def _first_instance(self) -> str | None:
        for e in self._events():
            resource = e.get("resource") or ""
            if resource.startswith("i-"):
                return resource
            if ":instance/" in resource:
                return resource.split(":instance/")[-1]
        return None

    def vulnerabilities(self, q: dict) -> dict:
        def build():
            resp = self._call(
                "inspector2", "list_findings",
                filterCriteria={"findingType": [
                    {"comparison": "EQUALS", "value": "PACKAGE_VULNERABILITY"}]},
                maxResults=MAX_ITEMS,
            )
            items = []
            for f in resp.get("findings", []):
                vd = f.get("packageVulnerabilityDetails") or {}
                pkg = (vd.get("vulnerablePackages") or [{}])[0]
                scores = vd.get("cvss") or []
                resource = (f.get("resources") or [{}])[0].get("id") or ""
                items.append({
                    "id": f.get("findingArn") or vd.get("vulnerabilityId") or "",
                    "cveId": vd.get("vulnerabilityId"),
                    "source": "Inspector",
                    "severity": f.get("severity") or "LOW",
                    "cvss": scores[0].get("baseScore") if scores else None,
                    "package": pkg.get("name"),
                    "installedVersion": pkg.get("version"),
                    "fixedVersion": pkg.get("fixedInVersion"),
                    "resource": resource,
                    "region": _region_of(resource, self.config.AWS_REGION),
                    "foundAt": _ms(f.get("firstObservedAt")),
                    "reportKey": None,
                })
            return {"items": items, "nextCursor": None}

        return self._cached("vulns", self.config.CACHE_TTL["vulnerabilities"], build)

    def execution_status(self, event_id: str, execution_id: str):
        event = self.get_event(event_id)
        if not event:
            return None
        run = self._call("ssm", "get_automation_execution",
                         AutomationExecutionId=execution_id).get("AutomationExecution") or {}
        status = enums.SSM_STATUS_TO_EXECUTION.get(run.get("AutomationExecutionStatus"), "RUNNING")
        steps = run.get("StepExecutions") or []
        execution = {
            "executionId": execution_id,
            "eventId": event_id,
            "kind": "REMEDIATION",
            "document": run.get("DocumentName"),
            "status": status,
            "startedAt": _ms(run.get("ExecutionStartTime")),
            "endedAt": _ms(run.get("ExecutionEndTime")),
            "progress": {
                "step": steps[-1].get("StepName") if steps else "실행 요청",
                "completed": sum(1 for s in steps if s.get("StepStatus") in ("Success", "Failed")),
                "total": len(steps) or 3,
            },
            "failureMessage": run.get("FailureMessage"),
        }
        event["execution"] = status
        return {"execution": execution, "event": event}

    # ── 쓰기 — 아직 스텁 ────────────────────────────────
    def _todo(self, name: str):
        raise ApiProblem(
            501, "실 AWS 쓰기가 아직 구현되지 않았습니다.", code="NOT_IMPLEMENTED",
            detail=f"{name}: {WRITE_PLAN.get(name, '')}",
        )

    def approve(self, event_id, body, actor, key):
        self._todo("approve")

    def execute(self, event_id, body, actor, key):
        self._todo("execute")

    def verify(self, event_id, body, actor, key):
        self._todo("verify")

    def cancel(self, event_id, body, actor, key):
        self._todo("cancel")

    # ── 상태 점검 ───────────────────────────────────────
    def health_checks(self) -> dict:
        """실모드에서 어떤 상류가 살아 있는지 알려준다.

        예외 메시지를 그대로 노출하지 않는다 — 권한 오류 본문에 ARN 이 섞인다
        (04-backend-design.md §4.3).
        """
        try:
            import boto3  # noqa: F401,PLC0415
        except ImportError:
            return {k: "skipped" for k in ("dynamodb", "cloudwatch", "securityhub", "ssm")}

        probes = {
            "dynamodb": lambda: self._client("dynamodb").describe_table(
                TableName=self.config.CORRELATED_FINDINGS_TABLE),
            "cloudwatch": lambda: self._client("cloudwatch").describe_alarms(MaxRecords=1),
            "securityhub": lambda: self._client("securityhub").describe_hub(),
            "ssm": lambda: self._client("ssm").describe_automation_executions(MaxResults=1),
        }
        checks = {}
        for name, probe in probes.items():
            try:
                probe()
                checks[name] = "ok"
            except Exception:  # noqa: BLE001 — 상세는 서버 로그에만
                checks[name] = "error"
        return checks


def _metric_query(qid: str, namespace: str, name: str, instance: str, period: int) -> dict:
    return {"Id": qid, "MetricStat": {
        "Metric": {"Namespace": namespace, "MetricName": name,
                   "Dimensions": [{"Name": "InstanceId", "Value": instance}]},
        "Period": period, "Stat": "Average"}}
