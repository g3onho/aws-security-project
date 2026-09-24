"""Canonical schema-v1 query validation and application facade.

This module has no Flask or AWS dependency. It accepts verified actor names,
rechecks their current principal through Workflow, and projects domain objects
into the design standard's DTOs. Legacy screen projections remain separate.
"""
import base64
import hashlib
import hmac
import json
import logging
import re
from datetime import datetime, timedelta, timezone
from urllib.parse import quote

from .errors import Problem
from .history_repository import HistoryRepository
from .repositories.correlations import apply as apply_correlations
from .scope import matches as scope_matches
from .store import encode, now_ms

ACTION_STATES = {
    "PENDING_APPROVAL", "APPROVED", "CANCELLED", "QUEUED", "RUNNING", "EXECUTED",
    "EXECUTION_FAILED", "VERIFY_QUEUED", "VERIFYING", "VERIFIED", "VERIFICATION_FAILED",
    "VERIFICATION_ERROR", "RECONCILING",
}
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL", "UNKNOWN")
COMMON = {"region", "resource", "from", "to"}
LIST = {"limit", "cursor"}
QUERY_FIELDS = {
    "events": COMMON | LIST | {"severity", "status"},
    "summary": COMMON | {"severity", "status"},
    "metrics": COMMON | {"periodSeconds"},
    "vulnerabilities": COMMON | LIST | {"severity", "source"},
    "infra": COMMON,
    "history": COMMON | LIST | {"eventId", "actionId", "jobId"},
}
# 자동조치 기록 status → 계약 actionState. 실행 성공(SUCCESS)은 EXECUTED 이지 VERIFIED(해결)가 아니다.
AUTOMATIC_STATES = {"NOTIFIED": "PENDING_APPROVAL", "DRY_RUN": "PENDING_APPROVAL", "IN_PROGRESS": "RUNNING",
                    "SUCCESS": "EXECUTED", "FAILED": "EXECUTION_FAILED", "TIMED_OUT": "EXECUTION_FAILED",
                    "CANCELLED": "EXECUTION_FAILED", "UNKNOWN": "RECONCILING"}
LEGACY_STATES = {
    "NEW": "PENDING_APPROVAL", "PENDING_APPROVAL": "PENDING_APPROVAL", "APPROVED": "APPROVED",
    "EXECUTING": "RUNNING", "PENDING_VERIFICATION": "EXECUTED", "VERIFYING": "VERIFYING",
    "RESOLVED": "VERIFIED", "EXECUTION_FAILED": "EXECUTION_FAILED",
    "VERIFICATION_FAILED": "VERIFICATION_FAILED",
}


def iso(value):
    if value is None:
        return None
    instant = datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(milliseconds=value)
    return instant.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def metadata(request_id, *, as_of=None, partial=False, warnings=None):
    return {"requestId": request_id, "schemaVersion": "1", "asOf": iso(now_ms() if as_of is None else as_of),
            "partial": bool(partial), "warnings": list(warnings or []), "dataMode": "live"}


def envelope(data, request_id, *, as_of=None, partial=False, warnings=None):
    return {"data": data, "meta": metadata(request_id, as_of=as_of, partial=partial, warnings=warnings)}


def parse_date(value, field):
    if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|\+00:00)", value):
        raise Problem(400, f"{field}는 UTC ISO 8601 날짜여야 합니다.", "INVALID_FILTER")
    try:
        instant = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return int((instant - datetime(1970, 1, 1, tzinfo=timezone.utc)).total_seconds() * 1000)
    except (ValueError, OverflowError) as error:
        raise Problem(400, f"{field} 날짜가 올바르지 않습니다.", "INVALID_FILTER") from error


def parse_query(raw, kind, default_to):
    if set(raw) - QUERY_FIELDS[kind]:
        raise Problem(400, "지원하지 않는 조회 필터입니다.", "INVALID_FILTER")
    values = {}
    for field, value in raw.items():
        if isinstance(value, list):
            if len(value) != 1:
                raise Problem(400, "같은 필터를 여러 번 지정할 수 없습니다.", "INVALID_FILTER")
            value = value[0]
        if not isinstance(value, str) or not value or len(value) > (4096 if field == "cursor" else 512):
            raise Problem(400, f"{field} 필터가 올바르지 않습니다.", "INVALID_FILTER")
        values[field] = value
    if ("from" in values) != ("to" in values):
        raise Problem(400, "from과 to는 함께 지정해야 합니다.", "INVALID_FILTER")
    q = dict(values)
    q["from"] = parse_date(values["from"], "from") if "from" in values else default_to - 86_400_000
    q["to"] = parse_date(values["to"], "to") if "to" in values else default_to
    if not 0 < q["to"] - q["from"] <= 31 * 86_400_000:
        raise Problem(400, "조회 구간은 0보다 크고 31일 이하여야 합니다.", "INVALID_FILTER")
    if "severity" in values and values["severity"] not in SEVERITIES:
        raise Problem(400, "severity 필터가 올바르지 않습니다.", "INVALID_FILTER")
    if "status" in values and values["status"] not in ACTION_STATES:
        raise Problem(400, "status 필터가 올바르지 않습니다.", "INVALID_FILTER")
    if kind in {"events", "vulnerabilities", "history"}:
        if not re.fullmatch(r"[0-9]{1,3}", values.get("limit", "50")):
            raise Problem(400, "limit은 1~200 정수여야 합니다.", "INVALID_FILTER")
        q["limit"] = int(values.get("limit", "50"))
        if not 1 <= q["limit"] <= 200:
            raise Problem(400, "limit은 1~200 정수여야 합니다.", "INVALID_FILTER")
    if kind == "metrics":
        if values.get("periodSeconds", "300") not in {"60", "300", "3600"}:
            raise Problem(400, "periodSeconds는 60, 300, 3600 중 하나여야 합니다.", "INVALID_FILTER")
        q["periodSeconds"] = int(values.get("periodSeconds", "300"))
    if kind == "vulnerabilities" and values.get("source", "Inspector") not in {"Inspector", "Trivy"}:
        raise Problem(400, "source는 Inspector 또는 Trivy여야 합니다.", "INVALID_FILTER")
    return q


def action_state(event):
    return event.get("actionState") or LEGACY_STATES.get(event.get("status"), "PENDING_APPROVAL")


def measurement(value):
    if not isinstance(value, dict):
        return None
    return {"value": value.get("value"), "unit": value.get("unit"),
            "observedAt": iso(value.get("at", value.get("observedAt"))),
            "source": value.get("source"), "criterionVersion": value.get("criterionVersion"),
            "resource": value.get("resource")}


def event_dto(event, allowed_actions):
    plan = event.get("plan") or {}
    return {"id": event["id"], "title": event["title"], "severity": event["severity"],
            "resource": event["resource"], "accountId": event.get("accountId"),
            "region": event["region"], "source": event["source"], "scenario": event["scenario"],
            "actionState": action_state(event), "version": event.get("version", 1),
            "allowedActions": list(allowed_actions), "updatedAt": iso(event.get("updatedAt", event["at"])),
            "observedAt": iso(event["at"]), "actionId": event.get("actionId"),
            "approvalId": event.get("approvalId"), "expiresAt": iso(event.get("expiresAt")),
            "playbookId": plan.get("document"), "playbookVersion": plan.get("version"),
            "parameters": plan.get("parameters", {}), "criterion": event.get("criterion"),
            "criterionVersion": event.get("criterionVersion"), "unit": event.get("unit"),
            "beforeState": measurement(event.get("before")), "afterState": measurement(event.get("after")),
            "verification": event.get("verification"),
            # 통합 관제 지도의 공격 흐름선. GuardDuty 출발지가 없으면 null.
            "sourceIp": event.get("sourceIp"), "sourceLocation": event.get("sourceLocation"),
            "geoStatus": event.get("geoStatus"), "sourceSample": bool(event.get("sourceSample")),
            # 플레이북이 없는 탐지(대부분의 Security Hub finding)는 승인 대상이 아니다 — 화면이 '탐지됨'으로 표시.
            "actionable": bool(event.get("actionable")),
            # correlator(DynamoDB)가 GuardDuty 위협 + 같은 자원 CVE 로 위험도를 올린 경우.
            "severityBumped": bool(event.get("severityBumped")), "relatedCves": list(event.get("relatedCves") or []),
            "dataMode": "live"}


def common_matches(row, q, timestamp, *, check_time=True):
    return (all(q.get(key) is None or q[key] == row.get(key) for key in ("region", "resource"))
            and (not check_time or (timestamp is not None and q["from"] <= timestamp < q["to"])))


class StandardService:
    def __init__(self, store, workflow, provider, cursor_secret, writes_enabled=True):
        self.store = store
        self.workflow = workflow
        self.provider = provider
        self.history = HistoryRepository(store)
        self.secret = str(cursor_secret).encode()
        self.writes_enabled = writes_enabled

    def _decode_cursor(self, token):
        try:
            payload, signature = token.split(".")
            expected = hmac.new(self.secret, payload.encode(), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(signature, expected):
                raise ValueError("signature")
            marker = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
            if (not isinstance(marker, dict) or type(marker.get("at")) is not int
                    or not isinstance(marker.get("id"), str) or not isinstance(marker.get("binding"), str)
                    or type(marker.get("from")) is not int or type(marker.get("to")) is not int):
                raise ValueError("shape")
            return marker
        except (ValueError, TypeError, KeyError, UnicodeError) as error:
            raise Problem(400, "페이지 커서가 올바르지 않습니다.", "INVALID_CURSOR") from error

    def _query(self, kind, raw, principal):
        default_to = now_ms() if kind == "history" else self.provider.as_of
        q = parse_query(raw, kind, default_to)
        marker = self._decode_cursor(q["cursor"]) if q.get("cursor") else None
        if marker and "from" not in raw and "to" not in raw:
            q.update({key: marker[key] for key in ("from", "to")})
        binding = hashlib.sha256(encode([kind, {key: value for key, value in q.items() if key != "cursor"}, principal]).encode()).hexdigest()
        if marker and marker["binding"] != binding:
            raise Problem(400, "커서의 필터 또는 사용자 범위가 달라졌습니다.", "INVALID_CURSOR")
        return q, binding, marker

    def _page(self, rows, q, binding, marker):
        rows = sorted(rows, key=lambda row: (-row["_sortAt"], row["id"]))
        if marker:
            rows = [row for row in rows if (-row["_sortAt"], row["id"]) > (-marker["at"], marker["id"])]
        page = rows[:q["limit"]]
        cursor = None
        if len(rows) > q["limit"]:
            last = page[-1]
            value = {"at": last["_sortAt"], "id": last["id"], "binding": binding,
                     "from": q["from"], "to": q["to"]}
            payload = base64.urlsafe_b64encode(encode(value).encode()).decode().rstrip("=")
            cursor = payload + "." + hmac.new(self.secret, payload.encode(), hashlib.sha256).hexdigest()
        return {"items": [{key: value for key, value in row.items() if not key.startswith("_")} for row in page],
                "nextCursor": cursor}

    def _events(self, actor, principal):
        # Both account scope and permissions are server-owned. Filtering never
        # broadens the current principal, including when a session is reused.
        connected = getattr(self.provider, "connected", False)
        source = self.provider.observations({}) if connected else self.workflow.events()
        if connected and hasattr(self.provider, "correlations"):
            try:
                source = apply_correlations(source, self.provider.correlations())
            except Exception:  # noqa: BLE001 — 상관분석은 부가 정보. 실패해도 이벤트는 그대로 보여준다.
                logging.getLogger(__name__).exception("correlation read failed")
        visible = []
        for event in source:
            if not scope_matches(event, principal):
                continue
            if not getattr(self.provider, "connected", False):
                self.workflow.authorize_event(event, actor, "dashboard:read")
            visible.append(event)
        return visible

    @staticmethod
    def _filtered(events, q):
        return [event for event in events if common_matches(event, q, event["at"])
                and (not q.get("severity") or event["severity"] == q["severity"])
                and (not q.get("status") or action_state(event) == q["status"])]

    def read(self, kind, raw, actor):
        self.provider.require_ready()
        principal = self.workflow.principal(actor)
        q, binding, marker = self._query(kind, raw, principal)
        events = self._events(actor, principal)
        if kind == "events":
            rows = [{**event_dto(event, self.workflow.allowed_actions(event, actor) if self.writes_enabled else []), "_sortAt": event["at"]}
                    for event in self._filtered(events, q)]
            return self._page(rows, q, binding, marker)
        if kind == "summary":
            rows = self._filtered(events, q)
            verified = sum(action_state(event) == "VERIFIED" for event in rows)
            return {"totalEvents": len(rows), "bySeverity": {severity: sum(event["severity"] == severity for event in rows) for severity in SEVERITIES},
                    "pendingApproval": sum(action_state(event) == "PENDING_APPROVAL" for event in rows),
                    "verifiedEvents": verified, "resolutionRate": round(100 * verified / len(rows), 2) if rows else None,
                    "scope": {"accounts": principal.get("scope", {}).get("accounts", []),
                              "regions": principal.get("scope", {}).get("regions"),
                              "resources": principal.get("scope", {}).get("resources"),
                              "region": q.get("region"), "resource": q.get("resource"), "from": iso(q["from"]), "to": iso(q["to"])},
                    "observedAt": iso(self.provider.as_of)}
        if kind == "vulnerabilities":
            rows = []
            for scan in self.provider.vulnerabilities(q, events)["items"]:
                # 기간 기준 = 가장 최근 탐지 시각(Inspector lastObservedAt). Inspector 는 같은 서버·CVE·패키지를
                # 기록 1건으로 두고 다시 탐지될 때마다 이 시각만 갱신한다. 최초 발견 시각(firstObservedAt)으로
                # 거르면 처음 발견 뒤 시간이 지나면 계속 탐지되는 CVE도 기간 보기에서 사라진다(v20.1).
                observed = scan.get("lastSeenAt") or scan.get("foundAt")
                if not scope_matches({"accountId": scan.get("accountId"), "region": scan.get("region"),
                                      "resource": scan.get("resource")}, principal) or not common_matches(scan, q, observed):
                    continue
                if (q.get("severity") and scan.get("severity") != q["severity"]
                        or q.get("source") and scan.get("source") != q["source"]):
                    continue
                rows.append({"id": scan["id"], "cveId": scan["cveId"], "resource": scan["resource"],
                             "resourceName": scan.get("resourceName"),
                             "package": scan["package"], "severity": scan["severity"], "source": scan["source"],
                             "region": scan["region"], "observedAt": iso(observed),
                             "firstObservedAt": iso(scan.get("foundAt")), "fixedVersion": scan.get("fixedVersion"),
                             "installedVersion": scan.get("installedVersion"), "cvss": scan.get("cvss"), "dataMode": "live", "_sortAt": observed})
            return self._page(rows, q, binding, marker)
        if kind == "history":
            return self._history(events, q, binding, marker, principal)
        if kind == "metrics":
            return self._metrics(q, principal)
        if kind == "infra":
            return self._infra(q, principal, events)
        raise Problem(404, "지원하지 않는 조회입니다.", "NOT_FOUND")

    def _resources(self, q, principal):
        rows = self.provider.resources({key: value for key, value in q.items() if key in {"region", "resource"}})["items"]
        return [row for row in rows if scope_matches({"region": row["region"], "resource": row["id"], "accountId": row.get("accountId")}, principal)]

    def _metrics(self, q, principal):
        series = []
        for resource in self._resources(q, principal):
            raw = self.provider.metric_for(resource, {**q, "region": resource["region"], "resource": resource["id"]})
            actual_period = raw.get("period")
            if actual_period != q["periodSeconds"]:
                raise Problem(422, "이 데이터 소스가 요청한 집계 주기를 지원하지 않습니다.", "UNSUPPORTED_PERIOD")
            for metric in ("cpu", "memory"):
                points = [{"timestamp": iso(point["at"]), "value": point.get(metric)}
                          for point in raw.get("points", []) if q["from"] <= point["at"] < q["to"]]
                # name: 인프라 모니터링 호스트 카드 제목(EC2 Name 태그). 없으면 화면이 ID 를 쓴다.
                series.append({"resource": resource["id"], "name": resource.get("name"), "region": resource["region"],
                               "metric": metric, "unit": "%",
                               "points": points, "observedAt": points[-1]["timestamp"] if points else None,
                               "collectionStatus": "available" if any(point["value"] is not None for point in points) else "missing"})
        return {"series": series, "thresholds": {"cpu": 80, "memory": 80}, "periodSeconds": q["periodSeconds"], "dataMode": "live"}

    def _infra(self, q, principal, events):
        components, dependencies = [], []
        status_map = {"UP": "healthy", "DEGRADED": "degraded", "DOWN": "unhealthy", "UNKNOWN": "unknown"}
        for resource in self._resources(q, principal):
            raw = self.provider.services({**q, "region": resource["region"], "resource": resource["id"]}, events)
            prefix = resource["region"] + "/" + resource["id"] + "/"
            for component in raw.get("items", []):
                components.append({"id": prefix + component["id"], "name": component["name"],
                                   "resource": resource["id"], "region": resource["region"],
                                   "status": status_map.get(component["status"], "unknown"),
                                   "observedAt": iso(raw.get("checkedAt")), "source": component.get("source"), "detail": component.get("detail")})
            dependencies.extend(raw.get("dependencies", []))
        return {"components": components, "dependencies": dependencies, "dataMode": "live"}

    @staticmethod
    def _evidence(event, *, record_id, actor, decision, created_at, updated_at, request_id=None, job_id=None, execution_id=None):
        plan = event.get("plan") or {}
        return {"id": record_id, "eventId": event["id"], "actionId": event.get("actionId"), "jobId": job_id,
                "actor": actor, "source": "automatic" if event.get("mode") == "AUTO" else "manual", "decision": decision,
                "playbookId": plan.get("document"), "playbookVersion": plan.get("version"),
                "parametersHash": hashlib.sha256(encode(plan.get("parameters", {})).encode()).hexdigest(),
                "beforeState": measurement(event.get("before")), "afterState": measurement(event.get("after")),
                "executionId": execution_id, "verification": event.get("verification"), "actionState": action_state(event),
                "createdAt": iso(created_at), "updatedAt": iso(updated_at), "requestId": request_id,
                "resource": event["resource"], "region": event["region"], "dataMode": "live"}

    def _automatic_history(self, principal, notes, finding_id=None):
        """DynamoDB 자동조치 기록 → Evidence 행. 설계 3.1: 외부 자동 SOAR 이력도 같은 조회 모델로."""
        if not hasattr(self.provider, "actions"):
            return []
        try:
            data = self.provider.actions(finding_id) if finding_id else self.provider.actions()
        except Exception:  # noqa: BLE001 — 내부 원인은 로그로만(설계 2.3 원칙 7)
            logging.getLogger(__name__).exception("action history read failed")
            notes["warnings"].append("자동조치 이력을 불러오지 못했습니다.")
            notes["partial"] = True
            return []
        if not data.get("configured"):
            notes["warnings"].append("자동조치 이력 테이블이 설정되지 않았습니다.")
            return []
        if data.get("truncated"):
            notes["warnings"].append("자동조치 이력이 많아 일부만 표시합니다.")
            notes["partial"] = True
        rows = []
        empty_hash = hashlib.sha256(encode({}).encode()).hexdigest()
        for record in data["items"]:
            # 리전·계정을 모르는 기록은 범위 제한 사용자에게 보이지 않는다(안전 쪽).
            if not scope_matches({"accountId": record["accountId"], "region": record["region"],
                                  "resource": record["resource"]}, principal):
                continue

            def text_state(text, at):
                return None if text is None else {"value": None, "unit": None, "observedAt": iso(at),
                                                  "source": "asr_trigger", "criterionVersion": None,
                                                  "resource": record["resource"], "text": text}
            rows.append({
                "id": "auto:" + record["actionId"] + "@" + str(record["createdAt"]),
                "eventId": record["eventId"], "actionId": record["actionId"], "jobId": None,
                "actor": "asr_trigger", "source": "automatic", "decision": record["decision"],
                "playbookId": record["playbookId"], "playbookVersion": None, "parametersHash": empty_hash,
                "beforeState": text_state(record["beforeText"], record["createdAt"]),
                "afterState": text_state(record["afterText"], record["updatedAt"]),
                "executionId": record["executionId"], "verification": "NOT_RUN",
                "actionState": AUTOMATIC_STATES.get(record["status"], "RECONCILING"),
                "automationStatus": record["status"], "occurrenceCount": record["occurrenceCount"],
                "findingId": record["findingId"], "findingType": record["findingType"],
                "createdAt": iso(record["createdAt"]), "updatedAt": iso(record["updatedAt"]),
                "lastSeenAt": iso(record["lastSeenAt"]), "requestId": None,
                "resource": record["resource"], "region": record["region"], "accountId": record["accountId"],
                "dataMode": "live", "_sortAt": record["lastSeenAt"]})
        return rows

    def _history(self, events, q, binding, marker, principal):
        known = {event["id"]: event for event in events}
        audits, jobs = self.history.snapshot()
        rows, selected_jobs = [], []
        for audit in audits:
            event = known.get(audit["event_id"])
            if not event:
                continue
            detail = audit["detail"]
            observed = detail.get("event") or {**event, "after": None, "verification": "NOT_RUN"}
            row = self._evidence(observed, record_id="audit:" + str(audit["id"]), actor=audit["actor"], decision=audit["action"],
                                 created_at=audit["at"], updated_at=audit["at"], request_id=detail.get("requestId"),
                                 job_id=detail.get("jobId", detail.get("executionId")), execution_id=detail.get("externalExecutionId"))
            row["_sortAt"] = audit["at"]
            row["reason"] = detail.get("reason")
            rows.append(row)
        for job in jobs:
            event = known.get(job["event_id"])
            if not event:
                continue
            captured = job["payload"]["event"]
            if not common_matches(event, q, job["created_at"], check_time=not bool(q.get("jobId"))):
                continue
            if any(q.get(field) and q[field] != value for field, value in (
                    ("eventId", event["id"]), ("actionId", captured.get("actionId")), ("jobId", job["id"]))):
                continue
            row = self._evidence(captured, record_id=job["id"], actor=job["payload"]["actor"], decision=job["kind"],
                                 created_at=job["created_at"], updated_at=job["updated_at"],
                                 request_id=job["payload"].get("requestId"), job_id=job["id"])
            states = ({"QUEUED": "QUEUED", "RUNNING": "RUNNING", "SUCCEEDED": "EXECUTED", "FAILED": "EXECUTION_FAILED"}
                      if job["kind"] == "execute" else
                      {"QUEUED": "VERIFY_QUEUED", "RUNNING": "VERIFYING", "SUCCEEDED": "VERIFIED" if (job["result"] or {}).get("passed") else "VERIFICATION_FAILED", "FAILED": "VERIFICATION_ERROR"})
            row.update(status=job["state"], actionState=states.get(job["state"], "RECONCILING"),
                       eventActionState=action_state(event), error=(job["result"] or {}).get("error"))
            if job["kind"] == "verify" and job["result"] and not job["result"].get("error"):
                row.update(afterState=measurement(job["result"]), verification="PASSED" if job["result"].get("passed") else "FAILED")
            selected_jobs.append(row)
        notes = {"warnings": [], "partial": False}
        # eventId 로 좁힌 조회는 그 이벤트의 finding 만 인덱스로 읽는다.
        finding_id = (known.get(q["eventId"]) or {}).get("externalFindingId") if q.get("eventId") else None
        rows.extend(self._automatic_history(principal, notes, finding_id))
        rows = [row for row in rows if common_matches(row, q, row["_sortAt"])
                and all(not q.get(field) or q[field] == row.get(field) for field in ("eventId", "actionId", "jobId"))]
        result = self._page(rows, q, binding, marker)
        result["jobs"] = sorted(selected_jobs, key=lambda row: (row["createdAt"], row["jobId"]), reverse=True)
        if notes["warnings"]:
            result["_warnings"], result["_partial"] = notes["warnings"], notes["partial"]
        return result

    def command(self, action, event_id, body, actor, key, request_id):
        self.provider.require_ready()
        # Canonical validation happens before the shared transaction. Version,
        # authorization and approval bindings are rechecked inside Workflow.
        if not self.writes_enabled:
            raise Problem(403, "현재 조회 전용 모드입니다.", "WRITE_DISABLED")
        if not isinstance(body, dict):
            raise Problem(400, "JSON 객체 본문이 필요합니다.", "INVALID_PARAMETER")
        try:
            encode(body)
        except (ValueError, TypeError) as error:
            raise Problem(400, "유한한 숫자를 포함한 JSON 본문이 필요합니다.", "INVALID_PARAMETER") from error
        required = {"expectedVersion", "reason", "playbookId", "parameters"} if action == "approve" else (
            {"expectedVersion", "reason"} if action == "cancel" else
            {"eventId", "expectedVersion", "approvalId" if action == "execute" else "actionId"})
        if set(body) != required:
            raise Problem(400, "필수 필드가 누락되었거나 허용되지 않은 필드가 있습니다.", "INVALID_PARAMETER")
        if type(body["expectedVersion"]) is not int or body["expectedVersion"] < 1:
            raise Problem(400, "expectedVersion은 양의 정수여야 합니다.", "INVALID_PARAMETER")
        if not isinstance(key, str) or not 1 <= len(key) <= 200 or not re.fullmatch(r"[\x21-\x7e]+", key):
            raise Problem(400, "유효한 Idempotency-Key가 필요합니다.", "INVALID_IDEMPOTENCY_KEY")
        translated = {"expected_version": body["expectedVersion"], "request_id": request_id}
        if action in {"approve", "cancel"}:
            if not isinstance(body["reason"], str) or not 1 <= len(body["reason"].strip()) <= 1000 or len(body["reason"]) > 1000:
                raise Problem(400, "reason은 1~1000자의 사유여야 합니다.", "INVALID_PARAMETER")
            translated["reason"] = body["reason"]
        if action == "approve":
            if not isinstance(body["playbookId"], str) or not body["playbookId"] or not isinstance(body["parameters"], dict):
                raise Problem(400, "playbookId와 parameters 형식이 올바르지 않습니다.", "INVALID_PARAMETER")
            translated.update(playbook_id=body["playbookId"], parameters=body["parameters"])
        if action in {"execute", "verify"}:
            identifier = "approvalId" if action == "execute" else "actionId"
            if any(not isinstance(body.get(field), str) or not body[field] or len(body[field]) > 512 for field in ("eventId", identifier)):
                raise Problem(400, "이벤트·조치 식별자가 올바르지 않습니다.", "INVALID_PARAMETER")
            event_id = body["eventId"]
            translated["approval_id" if action == "execute" else "action_id"] = body[identifier]
        result, status = self.workflow.change(event_id, action, translated, actor, key)
        event = result.get("event", result)
        response = {"eventId": event["id"], "actionId": event.get("actionId"),
                    "actionState": action_state(event), "version": event["version"]}
        if action == "approve":
            response.update(approvalId=event.get("approvalId"), expiresAt=iso(event.get("expiresAt")))
        if action in {"execute", "verify"}:
            job_id = result["execution"]["executionId"]
            response.update(jobId=job_id, statusUrl="/api/history?jobId=" + quote(job_id, safe=""))
        return response, status
