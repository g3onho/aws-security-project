"""Standard approve/cancel/execute routes keep their contract after legacy removal."""
import uuid

import pytest

from soar import create_app
from soar.auth import create_user
from soar.store import now_ms


class ConnectedProvider:
    connected = True
    regions = ("ap-northeast-2",)

    @property
    def as_of(self):
        return now_ms()

    def require_ready(self):
        return None

    def status(self):
        return {"connected": True, "state": "ready"}

    def observations(self, query=None):
        return []


def actionable_event(identifier):
    return {"id": identifier, "title": identifier, "accountId": "111", "region": "ap-northeast-2",
            "resource": "sg-1", "scenario": "SEC-01", "source": "Config", "severity": "HIGH",
            "environment": "dev", "status": "PENDING_APPROVAL", "actionState": "PENDING_APPROVAL",
            "mode": "MANUAL", "execution": "NOT_RUN", "verification": "NOT_RUN", "at": now_ms(),
            "version": 1, "actionable": True, "history": [], "before": None, "after": None,
            "criterion": "no 0.0.0.0/0", "criterionVersion": "1", "unit": "rules",
            "plan": {"document": "ASR-RevokeSecurityGroupIngress", "version": "1",
                     "parameters": {"SecurityGroupId": "sg-1"}}}


@pytest.fixture
def client(tmp_path):
    app = create_app({"TESTING": True, "DATABASE": str(tmp_path / "wf.sqlite3"),
                      "SECRET_KEY": "test", "WRITE_ENABLED": True})
    store = app.extensions["store"]
    create_user(store, "op", "test-password-123", "operator",
                {"accounts": None, "regions": None, "resources": None})
    provider = ConnectedProvider()
    app.extensions["provider"] = provider
    for name in ("standard_service", "workflow", "worker"):
        app.extensions[name].provider = provider
    with store.connect(write=True) as db:
        for identifier in ("e1", "e2"):
            store.save_event(db, actionable_event(identifier))
    client = app.test_client()
    token = client.get("/api/auth/session").json["csrfToken"]
    token = client.post("/api/auth/login", json={"username": "op", "password": "test-password-123"},
                        headers={"X-CSRF-Token": token}).json["csrfToken"]
    client.environ_base["HTTP_X_CSRF_TOKEN"] = token
    return client


def post(client, path, body, key=None):
    return client.post(path, json=body, headers={"Idempotency-Key": key or str(uuid.uuid4())})


def approve_body(version=1):
    return {"expectedVersion": version, "reason": "test", "playbookId": "ASR-RevokeSecurityGroupIngress",
            "parameters": {"SecurityGroupId": "sg-1"}}


def test_approve_then_execute_queues_a_job(client):
    approved = post(client, "/api/events/e1/approve", approve_body())
    assert approved.status_code == 200
    data = approved.json["data"]
    assert data["actionState"] == "APPROVED" and data["approvalId"] and data["version"] == 2
    queued = post(client, "/execute", {"eventId": "e1", "approvalId": data["approvalId"], "expectedVersion": 2})
    assert queued.status_code == 202
    assert queued.json["data"]["actionState"] == "QUEUED"
    assert queued.json["data"]["statusUrl"].startswith("/api/history?jobId=")


def test_cancel_and_version_conflict(client):
    assert post(client, "/api/events/e2/approve", approve_body(version=5)).status_code == 409
    cancelled = post(client, "/api/events/e2/cancel", {"expectedVersion": 1, "reason": "no"})
    assert cancelled.status_code == 200 and cancelled.json["data"]["actionState"] == "CANCELLED"


def test_idempotent_replay_and_key_conflict(client):
    key = str(uuid.uuid4())
    first = post(client, "/api/events/e1/approve", approve_body(), key)
    again = post(client, "/api/events/e1/approve", approve_body(), key)
    assert first.status_code == again.status_code == 200
    assert first.json["data"]["approvalId"] == again.json["data"]["approvalId"]
    assert post(client, "/api/events/e1/cancel", {"expectedVersion": 2, "reason": "x"}, key).status_code == 409


def test_changed_plan_parameters_are_rejected(client):
    body = approve_body()
    body["parameters"] = {"SecurityGroupId": "sg-other"}
    assert post(client, "/api/events/e1/approve", body).status_code == 422
