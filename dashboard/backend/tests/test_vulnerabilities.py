"""취약점(CVE) 목록 — 화면이 쓰지 않던 /api/vulnerabilities 를 실데이터로 채운 회차."""
from types import SimpleNamespace

from app.adapters.live import LiveAdapter, MAX_RESPONSE_ITEMS, PAGE_INSPECTOR
from app.catalog import loader


def _q(client, path):
    response = client.get(path)
    assert response.status_code == 200, response.json
    return response.json


def test_catalog_is_well_formed():
    catalog = loader.load_vulnerabilities()
    rows = catalog["vulnerabilities"]
    assert len(rows) > 100, "카탈로그가 100건을 넘어야 한다"
    targets = {t["id"] for t in catalog["targets"]}
    for row in rows:
        assert row["target"] in targets
        assert row["cveId"].startswith("CVE-")
        assert row["severity"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
        assert row["package"] and row["installedVersion"] and row["fixedVersion"]
        assert isinstance(row["cvss"], (int, float))


def test_fields_are_not_null_anymore(client):
    """이전 구현은 cveId·cvss·package·fixedVersion 을 전부 None 으로 돌려줬다."""
    data = _q(client, "/api/vulnerabilities")
    assert data["total"] > 100
    for item in data["items"][:50]:
        assert item["cveId"] and item["package"]
        assert item["installedVersion"] and item["fixedVersion"]
        assert item["cvss"] is not None


def test_sorted_by_severity_then_score(client):
    rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    keys = [(rank[i["severity"]], -(i["cvss"] or 0)) for i in _q(client, "/api/vulnerabilities")["items"]]
    assert keys == sorted(keys)


def test_groups_carry_an_actionable_event(client):
    """조치는 CVE 가 아니라 대상 단위다. 대상마다 걸 이벤트가 있어야 버튼이 뜬다."""
    data = _q(client, "/api/vulnerabilities")
    assert data["groups"]
    for group in data["groups"]:
        assert group["total"] >= 0 and "bySeverity" in group
        if group["total"]:
            assert group["eventId"], group["target"]
            assert group["eventStatus"]


def test_filters(client):
    total = _q(client, "/api/vulnerabilities")["total"]
    critical = _q(client, "/api/vulnerabilities?severity=CRITICAL")
    assert 0 < critical["total"] < total
    assert all(i["severity"] == "CRITICAL" for i in critical["items"])

    search = _q(client, "/api/vulnerabilities?q=openssl")
    assert 0 < search["total"] < total
    assert all("openssl" in (i["package"] or "").lower() for i in search["items"])

    target = _q(client, "/api/vulnerabilities")["groups"][0]["target"]
    scoped = _q(client, f"/api/vulnerabilities?resource={target}")
    assert scoped["total"] and all(i["target"] == target for i in scoped["items"])


def test_not_time_filtered(client):
    """스캔 결과는 이벤트가 아니다. 15분 구간을 골라도 목록이 비면 안 된다."""
    from app.adapters.demo import DEMO_NOW
    narrow = _q(client, f"/api/vulnerabilities?from={DEMO_NOW - 900000}&to={DEMO_NOW}")
    assert narrow["total"] == _q(client, "/api/vulnerabilities")["total"]
    assert narrow["timeFiltered"] is False


def test_response_is_not_capped_at_100(client):
    """상한이 100이던 회귀. 한 응답에 카탈로그 전량이 실려야 한다."""
    data = _q(client, "/api/vulnerabilities")
    assert data["total"] == len(data["items"]) > 100


# ── 실모드 ───────────────────────────────────────────────
def test_live_reads_every_inspector_page():
    """이전에는 _call(maxResults=100) 한 번이라 100건에서 잘렸다."""
    live = LiveAdapter(SimpleNamespace(AWS_REGION="ap-northeast-2", NAME_PREFIX="soar-sec-dev",
                                       CACHE_TTL={"vulnerabilities": 0, "metrics": 30},
                                       SCAN_RESULTS_BUCKET="", CORRELATED_FINDINGS_TABLE="",
                                       REMEDIATION_ACTIONS_TABLE=""))
    pages = [
        {"findings": [_finding(i) for i in range(PAGE_INSPECTOR)], "nextToken": "p2"},
        {"findings": [_finding(i) for i in range(PAGE_INSPECTOR, 150)]},
    ]
    seen = []

    def call(service, operation, **kwargs):
        if operation == "list_findings":
            seen.append(kwargs.get("nextToken"))
            assert kwargs["maxResults"] == PAGE_INSPECTOR
            return pages[len(seen) - 1]
        return {}

    live._call = call
    live._trivy_report_key = lambda: None
    live._events = lambda: []
    data = live.vulnerabilities({})
    assert len(seen) == 2, "두 번째 페이지를 읽지 않았다"
    assert data["total"] == 150
    assert data["summary"]["uniqueCves"] == 150
    assert data["truncated"] is False
    assert MAX_RESPONSE_ITEMS > 150


def _finding(index: int) -> dict:
    return {
        "findingArn": f"arn:finding:{index}",
        "severity": "HIGH",
        "resources": [{"id": "i-seoul-app-01"}],
        "packageVulnerabilityDetails": {
            "vulnerabilityId": f"CVE-2026-{index:04d}",
            "cvss": [{"baseScore": 7.5}],
            "vulnerablePackages": [{"name": "openssl", "version": "1.1.1k",
                                    "fixedInVersion": "1.1.1n"}],
        },
    }


# ── 재검증 CVE 집계 ───────────────────────────────────────
def _verifier():
    return LiveAdapter(SimpleNamespace(AWS_REGION="ap-northeast-2", NAME_PREFIX="soar-sec-dev",
                                       CACHE_TTL={"vulnerabilities": 0, "metrics": 30}))


def test_cve_count_reads_every_page():
    """100건에서 잘려 재검증 수치가 실제보다 작게 나오던 회귀."""
    live = _verifier()
    pages = [{"findings": [{}] * PAGE_INSPECTOR, "nextToken": "p2"},
             {"findings": [{}] * 37}]
    calls = []

    def call(service, operation, **kwargs):
        calls.append(kwargs)
        return pages[len(calls) - 1]

    live._call = call
    assert live._verify_cve_count({"resource": "i-seoul-app-01"}, {}) == 137
    assert len(calls) == 2


def test_cve_count_has_no_severity_filter_by_default():
    """SEC-04 criterion 이 '전체 심각도'다. 코드가 임의로 HIGH 이상을 걸면 문서와 어긋난다."""
    live = _verifier()
    seen = {}

    def call(service, operation, **kwargs):
        seen.update(kwargs)
        return {"findings": []}

    live._call = call
    live._verify_cve_count({"resource": "i-seoul-app-01"}, loader.get("SEC-04")["verify"])
    assert "severity" not in seen["filterCriteria"]


def test_cve_count_applies_min_severity_when_catalog_sets_one():
    live = _verifier()
    seen = {}

    def call(service, operation, **kwargs):
        seen.update(kwargs)
        return {"findings": []}

    live._call = call
    live._verify_cve_count({"resource": "i-x"}, {"min_severity": "HIGH"})
    values = [c["value"] for c in seen["filterCriteria"]["severity"]]
    assert values == ["CRITICAL", "HIGH"]


def test_sec04_is_verifiable_without_send_command():
    """이전에는 trivy_report_diff(ssm:SendCommand 필요)라 자동 재검증이 막혀 있었다."""
    spec = loader.get("SEC-04")["verify"]
    assert spec["type"] == "inspector_cve_count"
    assert loader.needs_send_command("SEC-04") is False
    # Trivy 경로는 버리지 않고 병행으로 남긴다.
    assert [a["type"] for a in spec["alternates"]] == ["trivy_report_diff"]
    assert spec["alternates"][0]["needs_send_command"] is True


def test_sec04_verification_is_automatic_in_live_mode(live_app):
    from app.adapters.live_service import LiveService
    service = live_app.extensions["dashboard_adapter"]
    assert isinstance(service, LiveService)
    event = service._decorate({
        "id": "x", "scenario": "SEC-04", "resource": "ecr/app:1.2", "region": "ap-northeast-2",
        "environment": "production", "recommendation": "이미지 교체", "criterionVersion": "v1",
        "status": "NEW", "at": 0,
    })
    assert event["verificationMethod"] == "aws"
