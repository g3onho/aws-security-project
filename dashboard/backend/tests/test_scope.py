"""Every standard read enforces the same account, region and resource scope."""
import pytest

from soar import create_app
from soar.auth import create_user
from soar.store import now_ms


class ScopedProvider:
    connected = True
    regions = ("ap-northeast-2", "us-east-1")

    @property
    def as_of(self):
        return now_ms()

    def require_ready(self):
        return None

    def status(self):
        return {"connected": True, "state": "ready"}

    def observations(self, query=None):
        return [self.event("a", "111", "ap-northeast-2", "i-allowed"),
                self.event("b", "222", "ap-northeast-2", "i-allowed"),
                self.event("c", "111", "us-east-1", "i-allowed"),
                self.event("d", "111", "ap-northeast-2", "i-other")]

    @staticmethod
    def event(identifier, account, region, resource):
        return {"id": identifier, "title": identifier, "accountId": account, "region": region,
                "resource": resource, "scenario": "SECURITY_HUB", "source": "Security Hub",
                "severity": "HIGH", "status": "PENDING_APPROVAL", "actionState": "PENDING_APPROVAL",
                "mode": "MANUAL", "execution": "NOT_RUN", "verification": "NOT_RUN",
                "at": now_ms() - 1000, "version": 1, "planHash": "test", "actionable": False,
                "allowedActions": [], "history": [], "before": None, "after": None,
                "criterionVersion": None}

    def vulnerabilities(self, query=None, events=None):
        return {"items": [{"id": "v-" + row["id"], "cveId": "CVE-2026-0001",
                           "accountId": row["accountId"], "resource": row["resource"],
                           "region": row["region"], "source": "Inspector", "severity": "HIGH",
                           "package": "pkg", "foundAt": row["at"]} for row in self.observations()],
                "total": 4}

    def resources(self, query=None):
        return {"items": [{"id": "i-allowed", "name": "allowed", "region": "ap-northeast-2",
                           "accountId": "111"}, {"id": "i-other", "name": "other",
                           "region": "ap-northeast-2", "accountId": "111"}], "total": 2}

    def metric_for(self, resource, query=None):
        return {"period": 300, "points": []}

    def services(self, query=None, events=None):
        return {"items": [{"id": "i-allowed", "name": "allowed", "status": "UP"},
                          {"id": "i-other", "name": "other", "status": "DOWN"}],
                "dependencies": []}


def test_scope_on_standard_reads(tmp_path):
    app = create_app({"TESTING": True, "DATABASE": str(tmp_path / "scope.sqlite3"),
                      "SECRET_KEY": "test", "WRITE_ENABLED": False})
    scope = {"accounts": ["111"], "regions": ["ap-northeast-2"], "resources": ["i-allowed"]}
    create_user(app.extensions["store"], "scoped", "test-password-123", "viewer", scope)
    provider = ScopedProvider()
    for name in ("provider",):
        app.extensions[name] = provider
    for name in ("standard_service", "workflow", "worker"):
        app.extensions[name].provider = provider
    client = app.test_client()
    token = client.get("/api/auth/session").json["csrfToken"]
    assert client.post("/api/auth/login", json={"username": "scoped", "password": "test-password-123"},
                       headers={"X-CSRF-Token": token}).status_code == 200

    assert [item["id"] for item in client.get("/api/events").json["data"]["items"]] == ["a"]
    assert client.get("/api/summary").json["data"]["totalEvents"] == 1
    assert [item["id"] for item in client.get("/api/vulnerabilities").json["data"]["items"]] == ["v-a"]
    # 자원 범위: 지표·인프라 상태는 허용된 자원(i-allowed)만 반환한다.
    assert {item["resource"] for item in client.get("/api/metrics").json["data"]["series"]} == {"i-allowed"}
    assert {item["resource"] for item in client.get("/api/infra/status").json["data"]["components"]} == {"i-allowed"}
    # 삭제된 호환 경로는 더 이상 응답하지 않는다.
    assert client.get("/api/legacy/events").status_code == 404
    scans = provider.vulnerabilities()
    provider.observations = lambda query=None: []
    provider.vulnerabilities = lambda query=None, events=None: scans
    assert [item["id"] for item in client.get("/api/vulnerabilities").json["data"]["items"]] == ["v-a"]


def test_default_empty_account_scope_does_not_reveal_aws_events(tmp_path):
    app = create_app({"TESTING": True, "DATABASE": str(tmp_path / "empty.sqlite3"),
                      "SECRET_KEY": "test", "WRITE_ENABLED": False})
    create_user(app.extensions["store"], "new", "test-password-123", "viewer")
    provider = ScopedProvider()
    app.extensions["provider"] = provider
    for name in ("standard_service", "workflow", "worker"):
        app.extensions[name].provider = provider
    client = app.test_client()
    token = client.get("/api/auth/session").json["csrfToken"]
    client.post("/api/auth/login", json={"username": "new", "password": "test-password-123"},
                headers={"X-CSRF-Token": token})
    assert client.get("/api/events").json["data"]["items"] == []
    assert client.get("/api/summary").json["data"]["totalEvents"] == 0
    assert client.get("/api/vulnerabilities").json["data"]["items"] == []


@pytest.mark.parametrize(("scope", "expected"), [
    ({"accounts": ["111"], "regions": None, "resources": None}, ["a", "d", "c"]),
    ({"accounts": None, "regions": ["ap-northeast-2"], "resources": None}, ["a", "b", "d"]),
    ({"accounts": None, "regions": None, "resources": ["i-allowed"]}, ["a", "b", "c"]),
])
def test_individual_scope_dimensions_match_between_apis(tmp_path, scope, expected):
    app = create_app({"TESTING": True, "DATABASE": str(tmp_path / "dimensions.sqlite3"),
                      "SECRET_KEY": "test", "WRITE_ENABLED": False})
    create_user(app.extensions["store"], "limited", "test-password-123", "viewer", scope)
    provider = ScopedProvider()
    app.extensions["provider"] = provider
    for name in ("standard_service", "workflow", "worker"):
        app.extensions[name].provider = provider
    client = app.test_client()
    token = client.get("/api/auth/session").json["csrfToken"]
    client.post("/api/auth/login", json={"username": "limited", "password": "test-password-123"},
                headers={"X-CSRF-Token": token})
    assert {row["id"] for row in client.get("/api/events").json["data"]["items"]} == set(expected)
    assert client.get("/api/summary").json["data"]["totalEvents"] == len(expected)
    assert {row["id"] for row in client.get("/api/vulnerabilities").json["data"]["items"]} == {"v-" + i for i in expected}
