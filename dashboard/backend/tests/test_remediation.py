"""대시보드 원클릭 조치: 계획 도출, 실행 게이트, 멱등성, 자동 재검증(SSM 성공 ≠ 해결)."""
import datetime as dt

import pytest

from soar import create_app
from soar.auth import create_user
from soar.demo import DemoProvider
from soar.remediation_plans import resolve

PASSWORD = "test-password-123"


def build(tmp_path, write=True):
    app = create_app({"TESTING": True, "DATABASE": str(tmp_path / "r.sqlite3"), "SECRET_KEY": "unit-test-only",
                      "WRITE_ENABLED": write, "DATA_PROVIDER": "demo", "PROJECT_VPC_ID": "vpc-0demo00000000001"})
    full = {"accounts": None, "regions": None, "resources": None}
    create_user(app.extensions["store"], "op", PASSWORD, "operator", scope=full)
    create_user(app.extensions["store"], "view", PASSWORD, "viewer", scope=full)
    return app


def login(app, name):
    client = app.test_client()
    token = client.get("/api/auth/session").json["csrfToken"]
    response = client.post("/api/auth/login", json={"username": name, "password": PASSWORD}, headers={"X-CSRF-Token": token})
    assert response.status_code == 200
    client.environ_base["HTTP_X_CSRF_TOKEN"] = response.json["csrfToken"]
    return client


@pytest.fixture(autouse=True)
def instant(monkeypatch):
    monkeypatch.setattr(DemoProvider, "RUN_SECONDS", 0)


def event_of(client, control):
    now = dt.datetime.now(dt.timezone.utc)
    q = f"from={(now - dt.timedelta(days=7)).strftime('%Y-%m-%dT%H:%M:%SZ')}&to={(now + dt.timedelta(minutes=1)).strftime('%Y-%m-%dT%H:%M:%SZ')}&limit=200"
    items = client.get("/api/events?" + q).json["data"]["items"]
    return next(e for e in items if e["controlId"] == control)["id"]


def run(client, event_id, key, reason="테스트"):
    plan = client.get(f"/api/events/{event_id}/remediation").json["data"]
    return client.post(f"/api/events/{event_id}/remediate", json={"reason": reason, "playbookId": plan["playbookId"]},
                       headers={"Idempotency-Key": key})


def test_plan_is_built_by_server_and_viewer_cannot_run(tmp_path):
    app = build(tmp_path)
    op, view = login(app, "op"), login(app, "view")
    event = event_of(op, "IAM.7")
    plan = op.get(f"/api/events/{event}/remediation").json["data"]
    assert plan["supported"] and plan["canExecute"] and plan["playbookId"] == "ASR-SetIamPasswordPolicy"
    assert view.get(f"/api/events/{event}/remediation").json["data"]["canExecute"] is False
    assert run(view, event, "view-key-1").status_code == 403
    wrong = op.post(f"/api/events/{event}/remediate", json={"reason": "x", "playbookId": "ASR-BlockS3AccountPublicAccess"},
                    headers={"Idempotency-Key": "wrong-key-1"})
    assert wrong.status_code == 409 and wrong.json["error"]["code"] == "PLAN_CHANGED"


def test_write_disabled_blocks_execution(tmp_path):
    app = build(tmp_path, write=False)
    op = login(app, "op")
    event = event_of(op, "IAM.7")
    assert op.get(f"/api/events/{event}/remediation").json["data"]["canExecute"] is False
    assert run(op, event, "ro-key-0001").status_code == 403


def test_execute_then_reverify_and_idempotent_replay(tmp_path):
    app = build(tmp_path)
    op = login(app, "op")
    event = event_of(op, "IAM.7")
    first = run(op, event, "iam7-key-01")
    assert first.status_code == 202 and first.json["data"]["state"] == "RUNNING"
    replay = run(op, event, "iam7-key-01")
    assert replay.json["data"]["id"] == first.json["data"]["id"]
    other = op.post(f"/api/events/{event}/remediate", json={"reason": "다른 사유", "playbookId": "ASR-SetIamPasswordPolicy"},
                    headers={"Idempotency-Key": "iam7-key-01"})
    assert other.status_code == 409 and other.json["error"]["code"] == "IDEMPOTENCY_CONFLICT"
    item = op.get(f"/api/remediations?eventId={event}").json["data"]["items"][0]
    assert item["state"] == "VERIFIED" and item["verification"]["passed"] is True and item["ssmStatus"] == "Success"
    assert item["before"]["text"] and item["reason"] == "테스트"
    hist = op.get("/api/history?from=%s&to=%s" % ((dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                                                   (dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=1)).strftime("%Y-%m-%dT%H:%M:%SZ")))
    assert [r["id"] for r in hist.json["data"]["remediations"]] == [item["id"]]


def test_stale_status_poll_cannot_restore_a_finished_run(tmp_path):
    app = build(tmp_path)
    op = login(app, "op")
    event = event_of(op, "IAM.7")
    started = run(op, event, "race-key-01").json["data"]
    service = app.extensions["remediation_service"]
    stale = service._get(started["id"])
    finished = op.get(f"/api/remediations?eventId={event}").json["data"]["items"][0]
    assert finished["state"] == "VERIFIED"
    service._save(stale, error="late read error")
    assert service._get(started["id"])["state"] == "VERIFIED"


def test_history_event_filter_applies_to_dashboard_remediations(tmp_path):
    app = build(tmp_path)
    op = login(app, "op")
    first, second = event_of(op, "IAM.7"), event_of(op, "SSM.6")
    run(op, first, "hist-iam-key")
    run(op, second, "hist-ssm-key")
    now = dt.datetime.now(dt.timezone.utc)
    query = "from=%s&to=%s&eventId=%s" % ((now - dt.timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                                          (now + dt.timedelta(minutes=1)).strftime("%Y-%m-%dT%H:%M:%SZ"), first)
    rows = op.get("/api/history?" + query).json["data"]["remediations"]
    assert [row["eventId"] for row in rows] == [first]


def test_already_compliant_is_not_executed(tmp_path):
    app = build(tmp_path)
    op = login(app, "op")
    response = run(op, event_of(op, "EC2.7"), "ebs-key-0001")
    assert response.status_code == 200 and response.json["data"]["state"] == "ALREADY_COMPLIANT"
    assert response.json["data"]["executionId"] is None


def test_ssm_failure_is_execution_failed(tmp_path):
    app = build(tmp_path)
    op = login(app, "op")
    event = event_of(op, "SSM.6")
    run(op, event, "ssm6-key-01")
    item = op.get(f"/api/remediations?eventId={event}").json["data"]["items"][0]
    assert item["state"] == "EXEC_FAILED" and "AccessDenied" in item["error"] and item["verification"] is None


def test_ssm_success_without_passing_reverify_is_not_resolved(tmp_path, monkeypatch):
    app = build(tmp_path)
    op = login(app, "op")
    provider = app.extensions["provider"]
    monkeypatch.setattr(provider, "remediation_measure", lambda plan: {"compliant": False, "text": "아직 미충족"})  # 실행 전·후 모두 미충족
    event = event_of(op, "IAM.7")
    run(op, event, "nores-key-01")
    item = op.get(f"/api/remediations?eventId={event}").json["data"]["items"][0]
    assert item["ssmStatus"] == "Success" and item["state"] == "NOT_RESOLVED"


def test_unreadable_reverify_is_an_error_not_a_pass(tmp_path, monkeypatch):
    app = build(tmp_path)
    op = login(app, "op")
    provider = app.extensions["provider"]

    real, calls = provider.remediation_measure, []

    def boom(plan):
        calls.append(1)
        if len(calls) > 2:          # 앞의 두 번은 미리보기·실행 전 확인, 그 뒤(재검증)부터 읽기 실패
            raise RuntimeError("denied")
        return real(plan)
    monkeypatch.setattr(provider, "remediation_measure", boom)
    event = event_of(op, "IAM.7")
    run(op, event, "verr-key-001")
    item = op.get(f"/api/remediations?eventId={event}").json["data"]["items"][0]
    assert item["state"] == "VERIFY_ERROR" and item["verification"]["passed"] is None


def test_untagged_group_and_foreign_region_are_blocked(tmp_path):
    app = build(tmp_path)
    op = login(app, "op")
    untagged = event_of(op, "EC2.18")
    plan = op.get(f"/api/events/{untagged}/remediation").json["data"]
    assert plan["canExecute"] is False and "태그" in plan["blockedReason"]
    assert run(op, untagged, "tag-key-0001").status_code == 409
    foreign = event_of(op, "EC2.53")
    assert "리전" in op.get(f"/api/events/{foreign}/remediation").json["data"]["blockedReason"]
    assert run(op, foreign, "reg-key-0001").json["error"]["code"] == "SCOPE_MISMATCH"


def test_second_run_while_active_is_rejected(tmp_path, monkeypatch):
    monkeypatch.setattr(DemoProvider, "RUN_SECONDS", 3600)
    app = build(tmp_path)
    op = login(app, "op")
    event = event_of(op, "IAM.7")
    assert run(op, event, "act-key-0001").status_code == 202
    again = run(op, event, "act-key-0002")
    assert again.status_code == 409 and again.json["error"]["code"] == "REMEDIATION_IN_PROGRESS"


def test_resolver_rejects_unsupported_inputs():
    key = {"controlId": None, "autoRemediation": {"mode": "auto", "playbookId": "ASR-DisableExposedAccessKey"}}
    assert resolve(key)["supported"] is False
    none = {"controlId": "EC2.7", "autoRemediation": {"mode": "none", "reason": "기록만"}}
    assert resolve(none)["eligible"] is False
    no_vpc = {"controlId": "EC2.2", "resource": "arn:aws:ec2:r:1:security-group/sg-0123456789abcdef0",
              "autoRemediation": {"mode": "conditional"}}
    assert resolve(no_vpc)["supported"] is False and resolve(no_vpc, "vpc-0123456789abcdef0")["parameters"]["VpcId"]
