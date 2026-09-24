"""DynamoDB 자동조치 기록·상관분석 연결 (v20 PR-3)."""
import time
from datetime import datetime, timedelta, timezone

import pytest

from soar import create_app
from soar.auth import create_user
from soar.integrations.aws.dynamodb import DynamoTable
from soar.repositories.actions import ActionRepository, normalize
from soar.repositories.findings import event_id
from soar.store import now_ms

NOW = datetime.now(timezone.utc)
iso = lambda d: d.isoformat().replace("+00:00", "Z")
SH = "arn:aws:securityhub:ap-northeast-2:111122223333:security-control/IAM.5/finding/57bc"
# 콘솔에서 본 v20 이전 기록 형식 그대로(2026-09-24)
OLD_ROW = {"action_id": "asr-1790215236", "created_at": iso(NOW - timedelta(minutes=30)), "after_state": "pending",
           "before_state": "n/a", "decision": "manual-notified", "finding_id": SH,
           "finding_type": "MFA should be enabled for all IAM users that have a console password",
           "resource_id": "arn:aws:iam::111122223333:user/admin", "ssm_execution_id": "n/a"}


def new_row(**over):
    row = {"action_id": "ssm-exec-1", "created_at": iso(NOW - timedelta(minutes=10)), "decision": "auto-executed",
           "status": "SUCCESS", "finding_id": "arn:aws:securityhub:ap-northeast-2:111122223333:finding/sg",
           "finding_type": "EC2.19", "resource_id": "sg-0abc", "region": "ap-northeast-2", "account_id": "111122223333",
           "playbook_id": "ASR-RevokeSecurityGroupIngress", "before_state": "sg:sg-0abc open",
           "after_state": "SSM Success", "ssm_execution_id": "exec-1", "occurrence_count": 1,
           "last_seen_at": iso(NOW - timedelta(minutes=5)), "updated_at": iso(NOW - timedelta(minutes=5)),
           "expires_at": int(time.time()) + 86400}
    row.update(over)
    return row


class FakeTable:
    def __init__(self, rows, truncated=False, index=False):
        self.rows, self.truncated, self.index, self.queried = rows, truncated, index, []

    def scan(self):
        return self.rows, self.truncated

    def query_index(self, index, key, value):
        self.queried.append((index, key, value))
        return [r for r in self.rows if r.get(key) == value] if self.index else None


def test_old_format_rows_get_region_account_and_event_link_from_the_arn():
    got = normalize(OLD_ROW)
    assert (got["region"], got["accountId"], got["status"]) == ("ap-northeast-2", "111122223333", "NOTIFIED")
    assert got["eventId"] == event_id(SH) and got["afterText"] is None and got["executionId"] is None
    assert got["occurrenceCount"] == 1


def test_expired_rows_are_hidden_even_before_ttl_deletion():
    repo = ActionRepository(FakeTable([new_row(), new_row(action_id="ssm-old", expires_at=int(time.time()) - 10)]))
    assert [r["actionId"] for r in repo.list()["items"]] == ["ssm-exec-1"]


def test_dynamo_scan_deserializes_caches_and_reports_truncation():
    calls = []
    client = type("DDB", (), {"scan": lambda self, **kw: calls.append(kw) or {"Items": [
        {"action_id": {"S": "a"}, "occurrence_count": {"N": "3"}, "cve_ids": {"L": [{"S": "CVE-1"}]}}]}})()
    session = type("S", (), {"client": lambda self, name: client})()
    table = DynamoTable(session, "t")
    rows, truncated = table.scan()
    assert rows == [{"action_id": "a", "occurrence_count": 3, "cve_ids": ["CVE-1"]}] and truncated is False
    table.scan()
    assert len(calls) == 1 and calls[0]["TableName"] == "t"


class Provider:
    connected = True
    regions = ("ap-northeast-2",)

    def __init__(self, rows=(), configured=True, fail=False, correlations=None):
        self.rows, self.configured, self.fail, self.corr = list(rows), configured, fail, correlations or {}

    @property
    def as_of(self):
        return now_ms()

    def require_ready(self):
        return None

    def status(self):
        return {"connected": True}

    def observations(self, query=None):
        at = now_ms() - 60000
        base = {"region": "ap-northeast-2", "accountId": "111122223333", "status": "PENDING_APPROVAL",
                "actionState": "PENDING_APPROVAL", "at": at, "version": 1, "actionable": False,
                "scenario": "위협 탐지", "verification": "NOT_RUN"}
        return [{**base, "id": "SH-GD", "title": "SSH brute force", "resource": "i-0aaa", "source": "GuardDuty",
                 "severity": "MEDIUM", "externalFindingId": "arn:aws:guardduty:ap-northeast-2:111122223333:detector/d/finding/gd-1"},
                {**base, "id": event_id(SH), "title": "MFA", "resource": "arn:aws:iam::111122223333:user/admin",
                 "source": "Security Hub", "severity": "LOW", "externalFindingId": SH}]

    def actions(self, finding_id=None):
        self.asked = finding_id
        if self.fail:
            raise RuntimeError("AccessDeniedException: secret internal detail")
        if not self.configured:
            return {"configured": False, "items": [], "truncated": False}
        repo = ActionRepository(FakeTable(self.rows))
        return {"configured": True, **(repo.for_finding(finding_id) if finding_id else repo.list())}

    def correlations(self):
        return self.corr


def client_for(tmp_path, provider, scope=None):
    app = create_app({"TESTING": True, "DATABASE": str(tmp_path / "h.sqlite3"), "SECRET_KEY": "t", "WRITE_ENABLED": False})
    create_user(app.extensions["store"], "u", "test-password-123", "viewer",
                scope or {"accounts": None, "regions": None, "resources": None})
    app.extensions["provider"] = provider
    for name in ("standard_service", "workflow", "worker"):
        app.extensions[name].provider = provider
    client = app.test_client()
    token = client.get("/api/auth/session").json["csrfToken"]
    client.post("/api/auth/login", json={"username": "u", "password": "test-password-123"}, headers={"X-CSRF-Token": token})
    return client


def test_history_includes_automatic_records_without_calling_execution_a_resolution(tmp_path):
    body = client_for(tmp_path, Provider([OLD_ROW, new_row()])).get("/api/history").json
    items = {row["actionId"]: row for row in body["data"]["items"]}
    auto = items["ssm-exec-1"]
    assert auto["source"] == "automatic" and auto["automationStatus"] == "SUCCESS"
    assert auto["actionState"] == "EXECUTED" and auto["verification"] == "NOT_RUN"  # 실행 ≠ 해결
    assert auto["afterState"]["text"] == "SSM Success" and auto["executionId"] == "exec-1"
    notified = items["asr-1790215236"]
    assert notified["actionState"] == "PENDING_APPROVAL" and notified["afterState"] is None
    assert notified["eventId"] == event_id(SH)
    assert body["meta"]["warnings"] == [] and body["meta"]["partial"] is False


def test_scope_hides_records_outside_or_without_account(tmp_path):
    rows = [OLD_ROW, new_row(), new_row(action_id="ssm-other", account_id="999999999999",
                                        finding_id="arn:aws:securityhub:ap-northeast-2:999999999999:finding/x"),
            {**OLD_ROW, "action_id": "asr-unknown", "finding_id": "gd-plain-id"}]
    scoped = {"accounts": ["111122223333"], "regions": None, "resources": None}
    ids = {row["actionId"] for row in client_for(tmp_path, Provider(rows), scoped).get("/api/history").json["data"]["items"]}
    assert ids == {"asr-1790215236", "ssm-exec-1"}


def test_missing_table_and_read_failure_are_reported_not_hidden(tmp_path):
    body = client_for(tmp_path, Provider(configured=False)).get("/api/history").json
    assert body["meta"]["warnings"] == ["자동조치 이력 테이블이 설정되지 않았습니다."] and body["meta"]["partial"] is False
    response = client_for(tmp_path / "b", Provider(fail=True)).get("/api/history")
    assert response.status_code == 200 and response.json["meta"]["partial"] is True
    assert "secret" not in response.get_data(as_text=True)


def test_correlation_bumps_guardduty_severity_on_the_server(tmp_path):
    corr = {"gd-1": {"bumped": True, "finalSeverity": "HIGH", "cves": ["CVE-2026-1"]}}
    client = client_for(tmp_path, Provider(correlations=corr))
    items = {row["id"]: row for row in client.get("/api/events").json["data"]["items"]}
    assert items["SH-GD"]["severity"] == "HIGH" and items["SH-GD"]["severityBumped"] is True
    assert items["SH-GD"]["relatedCves"] == ["CVE-2026-1"]
    assert items[event_id(SH)]["severityBumped"] is False
    assert client.get("/api/summary").json["data"]["bySeverity"]["HIGH"] == 1


@pytest.mark.parametrize("fail", [True])
def test_correlation_failure_does_not_break_events(tmp_path, fail):
    provider = Provider()
    provider.correlations = lambda: (_ for _ in ()).throw(RuntimeError("boom"))
    assert client_for(tmp_path, provider).get("/api/events").status_code == 200


def test_finding_history_uses_the_index_and_falls_back_to_scan_without_it():
    with_index = FakeTable([OLD_ROW, new_row()], index=True)
    got = ActionRepository(with_index).for_finding(SH)
    assert [r["actionId"] for r in got["items"]] == ["asr-1790215236"] and got["index"] is True
    assert with_index.queried == [("finding_id-created_at", "finding_id", SH)]
    without = ActionRepository(FakeTable([OLD_ROW, new_row()], index=False)).for_finding(SH)
    assert [r["actionId"] for r in without["items"]] == ["asr-1790215236"] and without["index"] is False


def test_index_permission_errors_become_none_but_other_errors_raise():
    from botocore.exceptions import ClientError

    def client_raising(code):
        def query(self, **kw):
            raise ClientError({"Error": {"Code": code, "Message": "x"}}, "Query")
        return type("S", (), {"client": lambda self, name: type("C", (), {"query": query})()})()
    assert DynamoTable(client_raising("AccessDeniedException"), "t").query_index("i", "k", "v") is None
    with pytest.raises(ClientError):
        DynamoTable(client_raising("ProvisionedThroughputExceededException"), "t").query_index("i", "k", "v")


def test_event_filtered_history_asks_only_for_that_finding(tmp_path):
    provider = Provider([OLD_ROW, new_row()])
    body = client_for(tmp_path, provider).get("/api/history?eventId=" + event_id(SH)).json
    assert provider.asked == SH
    assert [r["actionId"] for r in body["data"]["items"]] == ["asr-1790215236"]
